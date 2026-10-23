# client/backend/src/backend/local_auth.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from .crypto import IdentityKeyManager, PasswordKeyDeriver
from .relay_client import relay_request, restart_relay_listener, stop_relay_listener
from .state import AuthCredentialsPayload, state
from .storage import LocalStorage

# OAuth2PasswordBearer habilita o botão "Authorize" (Username + Password) no Swagger UI (/docs)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def require_authenticated_user(
    token: str | None = Depends(oauth2_scheme),
) -> str:
    """
    Dependência que exige que o cliente local esteja autenticado e habilita
    o cadeado / botão 'Authorize' no Swagger UI da API local.
    """
    effective_token = token or state.relay_jwt_token
    if not state.username or not effective_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nenhum usuário autenticado nesta instância local. Faça login no botão 'Authorize' ou em /auth/login.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return state.username


def get_relay_auth_headers(token: str | None = Depends(oauth2_scheme)) -> dict[str, str]:
    require_authenticated_user(token)
    effective_token = state.relay_jwt_token or token
    return {"Authorization": f"Bearer {effective_token}"}


def _normalize_username(username: str) -> str:
    clean_username = username.strip().lower()
    if not clean_username:
        raise HTTPException(status_code=400, detail="O nome de usuário não pode estar vazio.")
    return clean_username


def _token_response(status_message: str, **extra) -> dict:
    return {
        "access_token": state.relay_jwt_token,
        "token_type": "bearer",
        "username": state.username,
        "status": status_message,
        **extra,
    }


async def register_local_account(payload: AuthCredentialsPayload) -> dict:
    """
    1. Deriva duas chaves independentes (Split-Key) a partir da senha mestre.
    2. Gera o par de Chaves de Identidade ECDSA (SECP384R1).
    3. Cifra a chave privada de identidade com `local_storage_key` e salva no SQLite local.
    4. Envia apenas `relay_login_secret` e `public_identity_key` ao Servidor Relé.
    """
    clean_username = _normalize_username(payload.username)

    # 1. Split-Key Derivation
    local_storage_key, relay_login_secret = PasswordKeyDeriver.derive_master_keys(
        clean_username, payload.password
    )

    # 2. Gera par de Chaves de Identidade ECDSA
    id_manager = IdentityKeyManager()
    priv_key, pub_key = id_manager.generate_identity_key_pair()
    pub_pem = id_manager.export_public_key(pub_key).decode("utf-8")
    encrypted_priv_pem = id_manager.export_private_key(priv_key, local_storage_key=local_storage_key)

    # 3. Registra no Servidor Relé (sem nunca enviar a senha mestre real!)
    token_data = await relay_request(
        "POST",
        "/auth/register",
        json_body={
            "username": clean_username,
            "password": relay_login_secret,
            "public_identity_key": pub_pem,
        },
    )

    # 4. Salva identidade cifrada no banco local e ativa em memória
    LocalStorage(clean_username).save_my_identity(encrypted_priv_pem, pub_pem)

    state.username = clean_username
    state.local_storage_key = local_storage_key
    state.identity_private_key = priv_key
    state.identity_public_key_pem = pub_pem
    state.relay_jwt_token = token_data["access_token"]
    state.active_sessions = LocalStorage(clean_username).load_all_established_sessions(local_storage_key)

    await restart_relay_listener()
    return _token_response("Conta registrada com Split-Key e Identidade ECDSA.", public_identity_key=pub_pem)


async def perform_local_login(username: str, password: str) -> dict:
    """
    Fluxo unificado de login local (usado tanto por /auth/login quanto pelo botão Authorize do Swagger):
    1. Executa Split-Key Derivation (HKDF-SHA256) localmente.
    2. Desbloqueia a Chave Privada de Identidade ECDSA no SQLite local.
    3. Autentica no Servidor Relé usando `relay_login_secret` e conecta ao WebSocket.
    """
    clean_username = _normalize_username(username)

    local_storage_key, relay_login_secret = PasswordKeyDeriver.derive_master_keys(
        clean_username, password
    )

    stored_identity = LocalStorage(clean_username).get_my_identity()
    identity_private_key = None
    identity_public_key_pem = None

    if stored_identity:
        try:
            identity_private_key = IdentityKeyManager().load_private_key(
                stored_identity["encrypted_private_key_pem"],
                local_storage_key=local_storage_key,
            )
            identity_public_key_pem = stored_identity["public_key_pem"]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Senha incorreta para desbloquear o cofre de identidade local.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    token_data = await relay_request(
        "POST",
        "/auth/login",
        json_body={"username": clean_username, "password": relay_login_secret},
    )

    # Só altera o estado depois que o relé confirmou o login (evita estado parcial em caso de erro)
    state.username = clean_username
    state.local_storage_key = local_storage_key
    state.identity_private_key = identity_private_key
    state.identity_public_key_pem = identity_public_key_pem
    state.relay_jwt_token = token_data["access_token"]
    state.active_sessions = LocalStorage(clean_username).load_all_established_sessions(local_storage_key)

    await restart_relay_listener()
    return _token_response("Login realizado, cofre local desbloqueado e mensagens offline sincronizadas.")


async def logout_offline_mode(current_user: str) -> dict:
    """
    Desconecta o WebSocket do Servidor Relé (colocando este usuário em modo OFFLINE),
    preservando as sessões E2EE estabelecidas em memória.
    """
    await stop_relay_listener()
    state.relay_jwt_token = None
    return {
        "status": f"Usuário '{current_user}' desconectado do Relé (Modo Offline ativo).",
        "online": False,
    }
