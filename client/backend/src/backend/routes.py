# client/backend/src/backend/routes.py
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordRequestForm

from .audit import SecurityAuditor
from .local_auth import (
    get_relay_auth_headers,
    logout_offline_mode,
    perform_local_login,
    register_local_account,
    require_authenticated_user,
)
from .relay_client import persist_session_counters, relay_request, send_handshake_init
from .state import AuthCredentialsPayload, MessagePayload, state
from .storage import LocalStorage

auth_router = APIRouter(prefix="/auth", tags=["Autenticação"])
friends_router = APIRouter(tags=["Amigos & Descoberta"])
chat_router = APIRouter(prefix="/chat", tags=["Chat E2EE"])


# =============================================================================
# Rotas de Autenticação (/auth/*)
# =============================================================================
@auth_router.post("/register")
async def registrar_conta(payload: AuthCredentialsPayload):
    return await register_local_account(payload)


@auth_router.post("/login")
async def login_conta(payload: AuthCredentialsPayload):
    """Login via JSON (para o frontend React)."""
    return await perform_local_login(payload.username, payload.password)


@auth_router.post("/token", include_in_schema=False)
async def login_swagger_oauth2(form_data: OAuth2PasswordRequestForm = Depends()):
    """Endpoint OAuth2 acionado pelo botão 'Authorize' (Username + Password) do Swagger UI."""
    return await perform_local_login(form_data.username, form_data.password)


@auth_router.post("/logout")
async def logout_modo_offline(current_user: str = Depends(require_authenticated_user)):
    return await logout_offline_mode(current_user)


# =============================================================================
# Rotas de Descoberta de Usuários e Gestão de Amigos (proxy para o Relé)
# =============================================================================
@friends_router.get("/users/search")
async def buscar_usuarios(
    q: str = Query(..., min_length=1),
    headers: dict[str, str] = Depends(get_relay_auth_headers),
):
    return await relay_request("GET", "/users/search", headers=headers, params={"q": q})


@friends_router.get("/friends")
async def listar_amigos(headers: dict[str, str] = Depends(get_relay_auth_headers)):
    return await relay_request("GET", "/friends", headers=headers)


@friends_router.post("/friends/request/{contato}")
async def enviar_solicitacao_amizade(contato: str, headers: dict[str, str] = Depends(get_relay_auth_headers)):
    return await relay_request("POST", f"/friends/request/{contato}", headers=headers)


@friends_router.post("/friends/accept/{contato}")
async def aceitar_solicitacao_amizade(contato: str, headers: dict[str, str] = Depends(get_relay_auth_headers)):
    return await relay_request("POST", f"/friends/accept/{contato}", headers=headers)


@friends_router.post("/friends/reject/{contato}")
async def recusar_solicitacao_amizade(contato: str, headers: dict[str, str] = Depends(get_relay_auth_headers)):
    return await relay_request("POST", f"/friends/reject/{contato}", headers=headers)


@friends_router.delete("/friends/{contato}")
async def remover_amigo(contato: str, headers: dict[str, str] = Depends(get_relay_auth_headers)):
    contato_limpo = contato.strip().lower()
    res = await relay_request("DELETE", f"/friends/{contato_limpo}", headers=headers)
    # Remove também a sessão E2EE salva para que, se voltarem a ser amigos no futuro, possam fazer novo handshake
    state.active_sessions.pop(contato_limpo, None)
    if state.username:
        LocalStorage(state.username).delete_established_session(contato_limpo)
    return res


# =============================================================================
# Rotas de Chat E2EE (/chat/*)
# =============================================================================
@chat_router.post("/start/{contato}")
async def iniciar_chat(
    contato: str,
    current_user: str = Depends(require_authenticated_user),
):
    """O React chama esta rota quando o usuário clica num contato para iniciar o handshake."""
    contato = contato.strip().lower()
    sessao = state.active_sessions.get(contato)

    if sessao and sessao.is_established:
        return {"status": "Sessão E2EE já estabelecida.", "signed": state.identity_private_key is not None}

    if sessao and not sessao.is_established:
        return {
            "status": "Convite ECDH já enviado anteriormente. Aguardando resposta do contato.",
            "signed": state.identity_private_key is not None,
        }

    await send_handshake_init(contato, current_user)
    return {"status": "Convite ECDH enviado.", "signed": state.identity_private_key is not None}


@chat_router.post("/send/{contato}")
async def enviar_mensagem(
    contato: str,
    payload: MessagePayload,
    current_user: str = Depends(require_authenticated_user),
):
    """
    Cifra o texto com Serpent + HMAC e envia pelo Relé.
    - Se o contato estiver offline mas a sessão E2EE já existir: envia para a fila Store-and-Forward do Relé.
    - Se a sessão E2EE ainda não existir: inicia o handshake ECDH e agenda o envio automático!
    """
    if not state.relay_websocket:
        raise HTTPException(status_code=503, detail="Sem conexão com o relé.")

    contato = contato.strip().lower()
    sessao = state.active_sessions.get(contato)

    if not sessao or not sessao.is_established:
        if not sessao:
            await send_handshake_init(contato, current_user)
        state.pending_handshake_messages.setdefault(contato, []).append(payload.text)
        LocalStorage(current_user).save_message(
            contact_username=contato,
            is_sender=True,
            content=payload.text,
        )
        return {
            "status": (
                f"Aguardando handshake ECDH com '{contato}'. "
                "A mensagem será cifrada e enviada automaticamente assim que o handshake concluir!"
            )
        }

    mensagem = {
        "type": "CHAT_MESSAGE",
        "from": current_user,
        "to": contato,
        "payload": sessao.encrypt(payload.text).hex(),
    }
    persist_session_counters(contato, sessao)
    await state.relay_websocket.send(json.dumps(mensagem))

    LocalStorage(current_user).save_message(contact_username=contato, is_sender=True, content=payload.text)
    return {"status": "Mensagem cifrada e enviada."}


@chat_router.get("/safety-number/{contato}")
async def obter_safety_number(
    contato: str,
    current_user: str = Depends(require_authenticated_user),
):
    """O React chama esta rota para preencher o modal de segurança."""
    sessao = state.active_sessions.get(contato.strip().lower())
    if not sessao or not sessao.is_established:
        raise HTTPException(status_code=400, detail="Sessão não estabelecida.")
    return {"safety_number": sessao.get_safety_number()}


@chat_router.get("/history/{contato}")
async def obter_historico(
    contato: str,
    current_user: str = Depends(require_authenticated_user),
):
    """O React chama esta rota para carregar as mensagens antigas da tela."""
    historico = LocalStorage(current_user).get_chat_history(contato.strip().lower())
    return {"history": historico}


@chat_router.get("/audit-log")
async def obter_log_auditoria():
    """Retorna o passo a passo criptográfico (ECDH, ECDSA, HKDF, Serpent, HMAC, TOFU) desta instância."""
    return {"audit_log": SecurityAuditor.get_history()}
