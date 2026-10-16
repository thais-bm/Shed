import json

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

from .auth import create_access_token, get_current_user, hash_password, verify_access_token, verify_password
from .database import RelayDatabase
from .schemas import (
    FriendsListResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserPublic,
)

app = FastAPI(title="Shed Relay Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict[str, WebSocket] = {}


def get_db() -> RelayDatabase:
    return RelayDatabase()


@app.get("/")
async def relay_info() -> dict[str, str]:
    return {"service": "Shed Relé Server", "status": "ok"}


# Vê se o servidor está ativo e funcionando corretamente
@app.get("/health")
async def relay_health() -> dict[str, str]:
    return {"status": "ok"}


# =============================================================================
# Rotas de Autenticação (Registro e Login)
# =============================================================================
@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: RegisterRequest,
    db: RelayDatabase = Depends(get_db),
) -> TokenResponse:
    username = payload.username.strip().lower()
    pwd_hash = hash_password(payload.password)

    try:
        db.create_user(
            username=username,
            password_hash=pwd_hash,
            public_identity_key=payload.public_identity_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    token = create_access_token(username)
    return TokenResponse(access_token=token, username=username)


@app.post("/auth/login", response_model=TokenResponse)
async def login_user(
    payload: LoginRequest,
    db: RelayDatabase = Depends(get_db),
) -> TokenResponse:
    """Login via JSON (utilizado pela API local e clientes externos)."""
    username = payload.username.strip().lower()
    user = db.get_user(username)

    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(username)
    return TokenResponse(access_token=token, username=username)


@app.post("/auth/token", response_model=TokenResponse, include_in_schema=False)
async def login_swagger_oauth2(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: RelayDatabase = Depends(get_db),
) -> TokenResponse:
    """Endpoint OAuth2 interno acionado pelo botão 'Authorize' (Username + Password) do Swagger UI."""
    username = form_data.username.strip().lower()
    user = db.get_user(username)

    if user is None or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(username)
    return TokenResponse(access_token=token, username=username)


# =============================================================================
# Rotas de Descoberta de Usuários e Gestão de Amizades
# =============================================================================
@app.get("/users/search", response_model=list[UserPublic])
async def search_users(
    q: str = Query(..., min_length=1, description="Termo de busca pelo username"),
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> list[dict]:
    return db.search_users(query=q, exclude_username=current_user)


@app.get("/users/{target_username}/identity-key", response_model=UserPublic)
async def get_user_identity_key(
    target_username: str,
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> dict:
    user = db.get_user(target_username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )
    return {
        "username": user["username"],
        "public_identity_key": user["public_identity_key"],
        "created_at": user["created_at"],
    }


@app.get("/friends", response_model=FriendsListResponse)
async def list_friends(
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> dict[str, list[str]]:
    return db.get_friends_list(current_user)


@app.post("/friends/request/{target_username}")
async def send_friend_request(
    target_username: str,
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> dict[str, str]:
    try:
        resulting_status = db.send_friend_request(current_user, target_username)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "status": resulting_status,
        "target": target_username.strip().lower(),
    }


@app.post("/friends/accept/{requester_username}")
async def accept_friend_request(
    requester_username: str,
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> dict[str, str]:
    try:
        resulting_status = db.respond_friend_request(
            addressee=current_user,
            requester=requester_username,
            accept=True,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "status": resulting_status,
        "friend": requester_username.strip().lower(),
    }


@app.post("/friends/reject/{requester_username}")
async def reject_friend_request(
    requester_username: str,
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> dict[str, str]:
    try:
        resulting_status = db.respond_friend_request(
            addressee=current_user,
            requester=requester_username,
            accept=False,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "status": resulting_status,
        "requester": requester_username.strip().lower(),
    }


@app.delete("/friends/{friend_username}")
async def remove_friend(
    friend_username: str,
    current_user: str = Depends(get_current_user),
    db: RelayDatabase = Depends(get_db),
) -> dict[str, str]:
    removed = db.remove_friend(current_user, friend_username)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vínculo de amizade não encontrado.",
        )
    return {"status": "REMOVED", "friend": friend_username.strip().lower()}


# =============================================================================
# Conexão WebSocket de Roteamento E2EE
# =============================================================================
@app.websocket("/ws/{username}")
async def relay(
    websocket: WebSocket,
    username: str,
    token: str | None = Query(default=None),
) -> None:
    username = username.strip().lower()
    db = get_db()

    # Se o usuário está registrado no banco (ou enviou um token), valida o JWT obrigatoriamente
    registered_user = db.get_user(username)
    if registered_user is not None or token is not None:
        token_username = verify_access_token(token) if token else None
        if token_username != username:
            await websocket.accept()
            await websocket.close(code=1008, reason="Não autorizado: token inválido ou ausente")
            return

    await websocket.accept()

    previous_connection = connections.get(username)
    if previous_connection is not None:
        await previous_connection.close(code=1008, reason="Usuário conectado em outra sessão")

    connections[username] = websocket

    # Entrega imediatamente mensagens que chegaram enquanto o usuário estava offline
    for pending_envelope in db.pop_offline_messages(username):
        await websocket.send_text(pending_envelope)

    try:
        while True:
            raw_message = await websocket.receive_text()
            envelope = json.loads(raw_message)

            if str(envelope.get("from", "")).strip().lower() != username:
                await websocket.close(code=1008, reason="Remetente inválido")
                return

            recipient = envelope.get("to")
            if not isinstance(recipient, str) or not recipient.strip():
                await websocket.close(code=1008, reason="Destinatário ausente")
                return

            recipient = recipient.strip().lower()

            # Roteamento Friends-Only: usuários registrados só podem enviar envelopes para amigos aceitos
            if registered_user is not None and not db.are_friends(username, recipient):
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "ERROR",
                            "from": "relay",
                            "to": username,
                            "reason": f"Envio bloqueado: '{recipient}' não está na sua lista de amigos aceitos.",
                        }
                    )
                )
                continue

            destination = connections.get(recipient)
            if destination is not None:
                await destination.send_text(raw_message)
            else:
                # Store-and-Forward: guarda o envelope cifrado para quando o destinatário conectar
                db.save_offline_message(
                    recipient=recipient,
                    sender=username,
                    envelope_json=raw_message,
                )
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "OFFLINE_QUEUED",
                            "from": "relay",
                            "to": username,
                            "recipient": recipient,
                            "envelope_type": envelope.get("type", "UNKNOWN"),
                        }
                    )
                )
    except WebSocketDisconnect:
        return
    except json.JSONDecodeError:
        await websocket.close(code=1003, reason="Mensagem deve ser JSON válido")
    finally:
        if connections.get(username) is websocket:
            del connections[username]


# SERVIDOR PORTA 8000
def main() -> None:
    import uvicorn

    uvicorn.run("server:app", host="127.0.0.1", port=8000)
