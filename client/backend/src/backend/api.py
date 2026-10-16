# client/backend/src/backend/api.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .relay_client import stop_relay_listener
from .routes import auth_router, chat_router, friends_router
from .state import state


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia o desligamento limpo do listener WebSocket da API local."""
    yield
    await stop_relay_listener()


app = FastAPI(title="Shed Local API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite o React acessar
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registro dos módulos de rotas
app.include_router(auth_router)
app.include_router(friends_router)
app.include_router(chat_router)


@app.get("/", tags=["Status"])
async def api_info():
    return {
        "service": "Shed Local API",
        "username": state.username,
        "authenticated": state.relay_jwt_token is not None,
        "online": state.relay_websocket is not None,
        "status": "ok",
    }


@app.get("/health", tags=["Status"])
async def api_health():
    return {
        "status": "ok",
        "username": state.username,
        "authenticated": state.relay_jwt_token is not None,
        "online": state.relay_websocket is not None,
    }