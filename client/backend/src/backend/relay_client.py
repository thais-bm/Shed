# client/backend/src/backend/relay_client.py
import asyncio
import json
import httpx
import websockets
from fastapi import HTTPException

from .audit import SecurityAuditor
from .session import SecureSession
from .state import RELAY_HTTP_BASE_URL, RELAY_WS_BASE_URL, state
from .storage import LocalStorage


def get_relay_ws_url() -> str:
    if not state.username:
        raise RuntimeError("Usuário ainda não autenticado.")
    base = f"{RELAY_WS_BASE_URL}/ws/{state.username}"
    if state.relay_jwt_token:
        return f"{base}?token={state.relay_jwt_token}"
    return base


async def fetch_and_pin_peer_identity_key(peer_username: str) -> bytes | None:
    """
    Busca a Chave Pública de Identidade do contato no Servidor Relé
    e aplica a política TOFU (Trust On First Use) no banco SQLite local.
    """
    if not state.username:
        return None

    db = LocalStorage(state.username)
    pinned = db.get_pinned_contact_identity(peer_username)

    if not state.relay_jwt_token:
        return pinned.encode("utf-8") if pinned else None

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(
                f"{RELAY_HTTP_BASE_URL}/users/{peer_username}/identity-key",
                headers={"Authorization": f"Bearer {state.relay_jwt_token}"},
            )
            if res.status_code == 200:
                pub_pem = res.json().get("public_identity_key")
                if pub_pem:
                    db.verify_or_pin_contact_identity(peer_username, pub_pem)
                    return pub_pem.encode("utf-8")
    except ValueError:
        raise
    except Exception as exc:
        SecurityAuditor.log_step("API", f"Aviso ao consultar identidade de {peer_username}: {exc}")

    return pinned.encode("utf-8") if pinned else None


async def flush_pending_handshake_messages(contato: str, ws) -> None:
    """
    Assim que o handshake ECDH termina, cifra com Serpent e envia todas as
    mensagens que estavam aguardando na fila local.
    """
    pendentes = state.pending_handshake_messages.pop(contato, [])
    sessao = state.active_sessions.get(contato)
    if not pendentes or not sessao or not sessao.is_established or not state.username:
        return

    db = LocalStorage(state.username)
    for texto in pendentes:
        pacote_cifrado = sessao.encrypt(texto)
        mensagem = {
            "type": "CHAT_MESSAGE",
            "from": state.username,
            "to": contato,
            "payload": pacote_cifrado.hex(),
        }
        await ws.send(json.dumps(mensagem))
        db.save_message(contact_username=contato, is_sender=True, content=texto)
        SecurityAuditor.log_step(
            "API",
            f"Mensagem pendente cifrada e enviada para '{contato}' após conclusão do handshake.",
        )


async def send_handshake_init(contato: str, current_user: str) -> SecureSession:
    """Cria uma nova SecureSession, assina a chave efêmera ECDH com ECDSA e envia KEY_EXCHANGE_INIT."""
    if not state.relay_websocket:
        raise HTTPException(status_code=503, detail="Sem conexão com o relé.")

    sessao = SecureSession()
    state.active_sessions[contato] = sessao

    convite: dict[str, str] = {
        "type": "KEY_EXCHANGE_INIT",
        "from": current_user,
        "to": contato,
    }
    if state.identity_private_key is not None:
        pub_pem, sig = sessao.get_signed_public_key(state.identity_private_key)
        convite["public_key"] = pub_pem.decode("utf-8")
        convite["signature"] = sig.hex()
    else:
        convite["public_key"] = sessao.get_public_key().decode("utf-8")

    await state.relay_websocket.send(json.dumps(convite))
    return sessao


async def listen_to_relay() -> None:
    """
    Tarefa em background iniciada após o login/registro.
    Escuta o servidor relé, valida assinaturas ECDSA no handshake e decifra mensagens.
    """
    if not state.username or not state.relay_jwt_token:
        return

    ws_url = get_relay_ws_url()
    try:
        async with websockets.connect(ws_url) as ws:
            state.relay_websocket = ws
            SecurityAuditor.log_step("API", f"Conectado ao Relé Central como '{state.username}'")

            async for raw_message in ws:
                envelope = json.loads(raw_message)
                tipo = envelope.get("type")
                remetente = str(envelope.get("from", "")).strip().lower()

                if tipo == "ERROR":
                    SecurityAuditor.log_step(
                        "API",
                        "Erro retornado pelo Servidor Relé:",
                        envelope.get("reason", "Erro desconhecido"),
                    )
                    continue

                if tipo == "OFFLINE_QUEUED":
                    dest = envelope.get("recipient", "?")
                    env_type = envelope.get("envelope_type", "PACKET")
                    SecurityAuditor.log_step(
                        "API",
                        f"Destinatário '{dest}' está OFFLINE.",
                        f"Pacote {env_type} guardado com segurança na fila Store-and-Forward do Relé!",
                    )
                    continue

                if tipo == "KEY_EXCHANGE_INIT":
                    SecurityAuditor.log_step("API", f"Convite de E2EE recebido de {remetente}")
                    try:
                        peer_id_pub = await fetch_and_pin_peer_identity_key(remetente)
                        sig_hex = envelope.get("signature")
                        sig_bytes = bytes.fromhex(sig_hex) if sig_hex else None

                        nova_sessao = SecureSession()
                        nova_sessao.establish_session(
                            peer_public_key_pem=envelope["public_key"].encode("utf-8"),
                            signature=sig_bytes,
                            peer_identity_public_key_pem=peer_id_pub,
                        )
                        state.active_sessions[remetente] = nova_sessao

                        resposta: dict[str, str] = {
                            "type": "KEY_EXCHANGE_REPLY",
                            "from": state.username,
                            "to": remetente,
                        }
                        if state.identity_private_key is not None:
                            pub_pem, my_sig = nova_sessao.get_signed_public_key(state.identity_private_key)
                            resposta["public_key"] = pub_pem.decode("utf-8")
                            resposta["signature"] = my_sig.hex()
                        else:
                            resposta["public_key"] = nova_sessao.get_public_key().decode("utf-8")

                        await ws.send(json.dumps(resposta))
                        await flush_pending_handshake_messages(remetente, ws)
                    except ValueError as exc:
                        SecurityAuditor.log_step("API", f"Handshake de {remetente} REJEITADO!", str(exc))

                elif tipo == "KEY_EXCHANGE_REPLY":
                    SecurityAuditor.log_step("API", f"Resposta de E2EE recebida de {remetente}")
                    sessao = state.active_sessions.get(remetente)
                    if sessao:
                        try:
                            peer_id_pub = await fetch_and_pin_peer_identity_key(remetente)
                            sig_hex = envelope.get("signature")
                            sig_bytes = bytes.fromhex(sig_hex) if sig_hex else None

                            sessao.establish_session(
                                peer_public_key_pem=envelope["public_key"].encode("utf-8"),
                                signature=sig_bytes,
                                peer_identity_public_key_pem=peer_id_pub,
                            )
                            await flush_pending_handshake_messages(remetente, ws)
                        except ValueError as exc:
                            SecurityAuditor.log_step("API", f"Resposta de handshake de {remetente} REJEITADA!", str(exc))
                            del state.active_sessions[remetente]

                elif tipo == "CHAT_MESSAGE":
                    sessao = state.active_sessions.get(remetente)
                    if not sessao or not sessao.is_established:
                        SecurityAuditor.log_step(
                            "API",
                            f"Mensagem cifrada de '{remetente}' recebida sem sessão ativa.",
                            "Inicie ou renegocie o handshake ECDH.",
                        )
                        continue

                    payload_bytes = bytes.fromhex(envelope["payload"])
                    texto_limpo = sessao.decrypt(payload_bytes)

                    SecurityAuditor.log_step("API", f"Nova mensagem recebida de {remetente}", texto_limpo)

                    db = LocalStorage(state.username)
                    db.save_message(contact_username=remetente, is_sender=False, content=texto_limpo)

    except asyncio.CancelledError:
        SecurityAuditor.log_step("API", f"Conexão WebSocket encerrada para '{state.username}' (Modo Offline).")
    except Exception as exc:
        SecurityAuditor.log_step("API", f"Desconectado do Relé: {exc}")
    finally:
        state.relay_websocket = None


async def stop_relay_listener() -> None:
    """Encerra a conexão WebSocket com o Relé (coloca o cliente em modo Offline)."""
    if state.relay_websocket is not None:
        try:
            await state.relay_websocket.close()
        except Exception:
            pass
    if state.relay_listener_task and not state.relay_listener_task.done():
        state.relay_listener_task.cancel()
        try:
            await state.relay_listener_task
        except asyncio.CancelledError:
            pass
    state.relay_websocket = None
    state.relay_listener_task = None


async def restart_relay_listener() -> None:
    """Inicia ou reinicia a conexão WebSocket com o Relé após login/registro."""
    await stop_relay_listener()
    state.relay_listener_task = asyncio.create_task(listen_to_relay())
    await asyncio.sleep(0.2)
