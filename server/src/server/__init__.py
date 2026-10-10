import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI(title="Shed Relay Server")

connections: dict[str, WebSocket] = {}


@app.get("/")
async def relay_info() -> dict[str, str]:
    return {"service": "Shed Relé Server", "status": "ok"}

#Vê se o servidor está ativo e funcionando corretamente
@app.get("/health")
async def relay_health() -> dict[str, str]:
    return {"status": "ok"}

#Lida com a conexão WebSocket
@app.websocket("/ws/{username}")
async def relay(websocket: WebSocket, username: str) -> None:
    await websocket.accept()

    previous_connection = connections.get(username)
    if previous_connection is not None:
        await previous_connection.close(code=1008, reason="Usuário conectado em outra sessão")

    connections[username] = websocket

    try:
        while True:
            raw_message = await websocket.receive_text()
            envelope = json.loads(raw_message)

            if envelope.get("from") != username:
                await websocket.close(code=1008, reason="Remetente inválido")
                return

            recipient = envelope.get("to")
            if not isinstance(recipient, str) or not recipient:
                await websocket.close(code=1008, reason="Destinatário ausente")
                return

            destination = connections.get(recipient)
            if destination is not None:
                await destination.send_text(raw_message)
    except WebSocketDisconnect:
        return
    except json.JSONDecodeError:
        await websocket.close(code=1003, reason="Mensagem deve ser JSON válido")
    finally:
        if connections.get(username) is websocket:
            del connections[username]


#SERVIDOR PORTA 8000
def main() -> None:
    import uvicorn

    uvicorn.run("server:app", host="127.0.0.1", port=8000)
