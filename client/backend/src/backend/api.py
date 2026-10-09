# client/backend/src/backend/api.py
import asyncio
import json
import websockets
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel

from backend.session import SecureSession
from backend.audit import SecurityAuditor
from backend.storage import LocalStorage

# Configurações do usuário logado nesta máquina
MEU_USUARIO = "alice"
RELAY_URL = f"ws://127.0.0.1:8000/ws/{MEU_USUARIO}"

# Estado global em memória
# Mapeia: username_do_contato -> Instância de SecureSession
sessoes_ativas: dict[str, SecureSession] = {}
relay_websocket = None  # Conexão global com o servidor relé


# Modelos Pydantic para o React
class MessagePayload(BaseModel):
    text: str


async def listen_to_relay():
    """
    Tarefa em background que escuta eternamente o servidor relé.
    Recebe os pacotes, processa o handshake ou decifra a mensagem.
    """
    global relay_websocket
    try:
        async with websockets.connect(RELAY_URL) as ws:
            relay_websocket = ws
            SecurityAuditor.log_step("API", f"Conectado ao Relé Central como '{MEU_USUARIO}'")

            async for raw_message in ws:
                envelope = json.loads(raw_message)
                tipo = envelope.get("type")
                remetente = envelope.get("from")

                if tipo == "KEY_EXCHANGE_INIT":
                    SecurityAuditor.log_step("API", f"Convite de E2EE recebido de {remetente}")
                    # 1. Cria a sessão para esse contato
                    nova_sessao = SecureSession()

                    # 2. Processa a chave recebida
                    nova_sessao.establish_session(envelope["public_key"].encode())
                    sessoes_ativas[remetente] = nova_sessao

                    # 3. Responde com a própria chave pública
                    resposta = {
                        "type": "KEY_EXCHANGE_REPLY",
                        "from": MEU_USUARIO,
                        "to": remetente,
                        "public_key": nova_sessao.get_public_key().decode()
                    }
                    await ws.send(json.dumps(resposta))

                elif tipo == "KEY_EXCHANGE_REPLY":
                    SecurityAuditor.log_step("API", f"Resposta de E2EE recebida de {remetente}")
                    sessao = sessoes_ativas.get(remetente)
                    if sessao:
                        sessao.establish_session(envelope["public_key"].encode())
                        # Aqui o canal está 100% estabelecido!

                elif tipo == "CHAT_MESSAGE":
                    sessao = sessoes_ativas.get(remetente)
                    if not sessao or not sessao.is_established:
                        continue

                    # O motor Serpent decifra e valida o HMAC
                    payload_bytes = bytes.fromhex(envelope["payload"])
                    texto_limpo = sessao.decrypt(payload_bytes)

                    SecurityAuditor.log_step("API", f"Nova mensagem recebida de {remetente}", texto_limpo)

                    # Salva no banco de dados local a mensagem que acabou de chegar
                    db = LocalStorage(MEU_USUARIO)
                    db.save_message(contact_username=remetente, is_sender=False, content=texto_limpo)

    except Exception as e:
        SecurityAuditor.log_step("API", f"Desconectado do Relé: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia a inicialização e desligamento do app local."""
    task = asyncio.create_task(listen_to_relay())
    yield
    task.cancel()


# Inicialização da API Local
app = FastAPI(title="Shed Local API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite o React acessar
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/chat/start/{contato}")
async def iniciar_chat(contato: str):
    """O React chama esta rota quando o usuário clica num contato para iniciar o handshake."""
    global relay_websocket
    if not relay_websocket:
        raise HTTPException(status_code=503, detail="Sem conexão com o relé.")

    sessao = SecureSession()
    sessoes_ativas[contato] = sessao

    convite = {
        "type": "KEY_EXCHANGE_INIT",
        "from": MEU_USUARIO,
        "to": contato,
        "public_key": sessao.get_public_key().decode()
    }
    await relay_websocket.send(json.dumps(convite))
    return {"status": "Convite ECDH enviado."}


@app.post("/chat/send/{contato}")
async def enviar_mensagem(contato: str, payload: MessagePayload):
    """O React chama esta rota com o texto limpo. A API cifra e joga na rede."""
    sessao = sessoes_ativas.get(contato)
    if not sessao or not sessao.is_established:
        raise HTTPException(status_code=400, detail="Sessão não estabelecida.")

    # Cifra o texto com Serpent + HMAC
    pacote_cifrado = sessao.encrypt(payload.text)

    mensagem = {
        "type": "CHAT_MESSAGE",
        "from": MEU_USUARIO,
        "to": contato,
        "payload": pacote_cifrado.hex()
    }

    await relay_websocket.send(json.dumps(mensagem))

    # Salva no banco local a mensagem enviada
    db = LocalStorage(MEU_USUARIO)
    db.save_message(contact_username=contato, is_sender=True, content=payload.text)

    return {"status": "Mensagem cifrada e enviada."}


@app.get("/chat/safety-number/{contato}")
async def obter_safety_number(contato: str):
    """O React chama esta rota para preencher o modal de segurança."""
    sessao = sessoes_ativas.get(contato)
    if not sessao or not sessao.is_established:
        raise HTTPException(status_code=400, detail="Sessão não estabelecida.")
    return {"safety_number": sessao.get_safety_number()}


@app.get("/chat/history/{contato}")
async def obter_historico(contato: str):
    """O React chama esta rota para carregar as mensagens antigas da tela."""
    db = LocalStorage(MEU_USUARIO)
    historico = db.get_chat_history(contato)
    return {"history": historico}