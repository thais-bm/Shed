# client/backend/src/backend/state.py
import asyncio
from pydantic import BaseModel
from .session import SecureSession

# Endereços fixos do Servidor Relé Central
RELAY_WS_BASE_URL = "ws://127.0.0.1:8000"
RELAY_HTTP_BASE_URL = "http://127.0.0.1:8000"


# Modelos Pydantic compartilhados
class MessagePayload(BaseModel):
    text: str


class AuthCredentialsPayload(BaseModel):
    username: str
    password: str


class ClientState:
    """
    Centraliza o estado em memória da instância local do cliente,
    evitando variáveis globais espalhadas entre múltiplos arquivos.
    """

    def __init__(self) -> None:
        self.username: str | None = None
        self.relay_jwt_token: str | None = None
        self.local_storage_key: bytes | None = None
        self.identity_private_key = None
        self.identity_public_key_pem: str | None = None

        # Mapeia: username_do_contato -> Instância de SecureSession
        self.active_sessions: dict[str, SecureSession] = {}
        # Fila local de mensagens aguardando término do handshake ECDH
        self.pending_handshake_messages: dict[str, list[str]] = {}
        # Fila local de payloads cifrados recebidos enquanto o handshake ainda estava em andamento
        self.pending_incoming_ciphertexts: dict[str, list[str]] = {}

        # Conexão e tarefa de background do WebSocket com o Relé
        self.relay_websocket = None
        self.relay_listener_task: asyncio.Task | None = None


state = ClientState()
