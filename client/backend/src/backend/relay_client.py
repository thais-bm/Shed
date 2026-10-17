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


# =============================================================================
# Comunicação HTTP com o Relé
# =============================================================================
async def relay_request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict | None = None,
    json_body: dict | None = None,
) -> dict:
    """
    Faz uma requisição HTTP ao Servidor Relé e converte erros em HTTPException,
    repassando a mensagem de erro original do relé para o cliente.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.request(
            method,
            f"{RELAY_HTTP_BASE_URL}{path}",
            headers=headers,
            params=params,
            json=json_body,
        )

    if not res.is_success:
        try:
            detail = res.json().get("detail", res.text)
        except ValueError:
            detail = res.text
        raise HTTPException(
            status_code=res.status_code,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"} if res.status_code == 401 else None,
        )
    return res.json()


async def fetch_and_pin_peer_identity_key(peer_username: str) -> bytes | None:
    """
    Busca a Chave Pública de Identidade do contato no Servidor Relé
    e aplica a política TOFU (Trust On First Use) no banco SQLite local.
    """
    if not state.username:
        return None

    db = LocalStorage(state.username)
    pinned = db.get_pinned_contact_identity(peer_username)

    if state.relay_jwt_token:
        try:
            data = await relay_request(
                "GET",
                f"/users/{peer_username}/identity-key",
                headers={"Authorization": f"Bearer {state.relay_jwt_token}"},
            )
            pub_pem = data.get("public_identity_key")
            if pub_pem:
                # Dispara ValueError se a chave divergir da fixada (possível MitM)
                db.verify_or_pin_contact_identity(peer_username, pub_pem)
                return pub_pem.encode("utf-8")
        except HTTPException as exc:
            SecurityAuditor.log_step("API", f"Aviso ao consultar identidade de {peer_username}: {exc.detail}")

    return pinned.encode("utf-8") if pinned else None


# =============================================================================
# Construção de Envelopes do Handshake
# =============================================================================
def _build_key_exchange_envelope(tipo: str, contato: str, sessao: SecureSession) -> dict[str, str]:
    """Monta um envelope KEY_EXCHANGE_* com a chave efêmera ECDH (assinada com ECDSA, se houver identidade)."""
    envelope = {"type": tipo, "from": state.username, "to": contato}
    if state.identity_private_key is not None:
        pub_pem, sig = sessao.get_signed_public_key(state.identity_private_key)
        envelope["public_key"] = pub_pem.decode("utf-8")
        envelope["signature"] = sig.hex()
    else:
        envelope["public_key"] = sessao.get_public_key().decode("utf-8")
    return envelope


async def _establish_from_envelope(sessao: SecureSession, remetente: str, envelope: dict) -> None:
    """Valida a assinatura ECDSA (com TOFU) do envelope recebido e deriva a chave de sessão Serpent."""
    peer_id_pub = await fetch_and_pin_peer_identity_key(remetente)
    sig_hex = envelope.get("signature")
    sessao.establish_session(
        peer_public_key_pem=envelope["public_key"].encode("utf-8"),
        signature=bytes.fromhex(sig_hex) if sig_hex else None,
        peer_identity_public_key_pem=peer_id_pub,
    )


async def send_handshake_init(contato: str, current_user: str) -> SecureSession:
    """Cria uma nova SecureSession, assina a chave efêmera ECDH com ECDSA e envia KEY_EXCHANGE_INIT."""
    if not state.relay_websocket:
        raise HTTPException(status_code=503, detail="Sem conexão com o relé.")

    sessao = SecureSession()
    state.active_sessions[contato] = sessao
    convite = _build_key_exchange_envelope("KEY_EXCHANGE_INIT", contato, sessao)
    await state.relay_websocket.send(json.dumps(convite))
    return sessao


async def flush_pending_handshake_messages(contato: str, ws) -> None:
    """
    Assim que o handshake ECDH termina, cifra com Serpent e envia todas as
    mensagens que estavam aguardando na fila local.
    """
    pendentes = state.pending_handshake_messages.pop(contato, [])
    sessao = state.active_sessions.get(contato)
    if not pendentes or not sessao or not sessao.is_established or not state.username:
        return

    for texto in pendentes:
        mensagem = {
            "type": "CHAT_MESSAGE",
            "from": state.username,
            "to": contato,
            "payload": sessao.encrypt(texto).hex(),
        }
        await ws.send(json.dumps(mensagem))
        SecurityAuditor.log_step(
            "API",
            f"Mensagem pendente cifrada e enviada para '{contato}' após conclusão do handshake.",
        )


# =============================================================================
# Handlers de Envelopes Recebidos do Relé
# =============================================================================
async def _handle_error(ws, remetente: str, envelope: dict) -> None:
    SecurityAuditor.log_step("API", "Erro retornado pelo Servidor Relé:", envelope.get("reason", "Erro desconhecido"))


async def _handle_offline_queued(ws, remetente: str, envelope: dict) -> None:
    SecurityAuditor.log_step(
        "API",
        f"Destinatário '{envelope.get('recipient', '?')}' está OFFLINE.",
        f"Pacote {envelope.get('envelope_type', 'PACKET')} guardado com segurança na fila Store-and-Forward do Relé!",
    )


async def _handle_key_exchange_init(ws, remetente: str, envelope: dict) -> None:
    SecurityAuditor.log_step("API", f"Convite de E2EE recebido de {remetente}")
    nova_sessao = SecureSession()
    await _establish_from_envelope(nova_sessao, remetente, envelope)
    state.active_sessions[remetente] = nova_sessao

    resposta = _build_key_exchange_envelope("KEY_EXCHANGE_REPLY", remetente, nova_sessao)
    await ws.send(json.dumps(resposta))
    await flush_pending_handshake_messages(remetente, ws)


async def _handle_key_exchange_reply(ws, remetente: str, envelope: dict) -> None:
    SecurityAuditor.log_step("API", f"Resposta de E2EE recebida de {remetente}")
    sessao = state.active_sessions.get(remetente)
    if not sessao:
        return
    try:
        await _establish_from_envelope(sessao, remetente, envelope)
    except ValueError:
        # Handshake comprometido: descarta a sessão para não cifrar com chaves não autenticadas
        state.active_sessions.pop(remetente, None)
        raise
    await flush_pending_handshake_messages(remetente, ws)


async def _handle_chat_message(ws, remetente: str, envelope: dict) -> None:
    sessao = state.active_sessions.get(remetente)
    if not sessao or not sessao.is_established:
        SecurityAuditor.log_step(
            "API",
            f"Mensagem cifrada de '{remetente}' recebida sem sessão ativa.",
            "Inicie ou renegocie o handshake ECDH.",
        )
        return

    # O motor Serpent valida o HMAC e decifra (ValueError se o pacote foi adulterado)
    texto_limpo = sessao.decrypt(bytes.fromhex(envelope["payload"]))
    SecurityAuditor.log_step("API", f"Nova mensagem recebida de {remetente}", texto_limpo)
    LocalStorage(state.username).save_message(contact_username=remetente, is_sender=False, content=texto_limpo)


_ENVELOPE_HANDLERS = {
    "ERROR": _handle_error,
    "OFFLINE_QUEUED": _handle_offline_queued,
    "KEY_EXCHANGE_INIT": _handle_key_exchange_init,
    "KEY_EXCHANGE_REPLY": _handle_key_exchange_reply,
    "CHAT_MESSAGE": _handle_chat_message,
}


# =============================================================================
# Ciclo de Vida da Conexão WebSocket
# =============================================================================
def get_relay_ws_url() -> str:
    if not state.username or not state.relay_jwt_token:
        raise RuntimeError("Usuário ainda não autenticado.")
    return f"{RELAY_WS_BASE_URL}/ws/{state.username}?token={state.relay_jwt_token}"


async def listen_to_relay() -> None:
    """
    Tarefa em background iniciada após o login/registro.
    Escuta o servidor relé e despacha cada envelope para o handler correspondente.
    """
    if not state.username or not state.relay_jwt_token:
        return

    try:
        async with websockets.connect(get_relay_ws_url()) as ws:
            state.relay_websocket = ws
            SecurityAuditor.log_step("API", f"Conectado ao Relé Central como '{state.username}'")

            async for raw_message in ws:
                try:
                    envelope = json.loads(raw_message)
                    tipo = envelope.get("type")
                    remetente = str(envelope.get("from", "")).strip().lower()

                    handler = _ENVELOPE_HANDLERS.get(tipo)
                    if handler is None:
                        SecurityAuditor.log_step("API", f"Envelope de tipo desconhecido ignorado: {tipo}")
                        continue
                    await handler(ws, remetente, envelope)

                except (ValueError, KeyError, AttributeError) as exc:
                    # Um pacote inválido/adulterado é descartado sem derrubar a conexão
                    SecurityAuditor.log_step("API", "Pacote recebido REJEITADO e descartado.", str(exc))

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
