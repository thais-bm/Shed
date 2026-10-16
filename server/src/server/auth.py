import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash

# Configurações do JWT
SECRET_KEY = os.getenv("SHED_JWT_SECRET", "shed-dev-secret-key-change-in-production-32bytes!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Motor Argon2 para hash seguro de senhas
password_hasher = PasswordHash.recommended()

# OAuth2PasswordBearer faz o botão "Authorize" do Swagger (/docs) pedir Username e Password!
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def hash_password(plain_password: str) -> str:
    """Gera o hash Argon2 da senha em texto limpo."""
    return password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Valida se a senha em texto limpo corresponde ao hash Argon2 salvo."""
    return password_hasher.verify(plain_password, hashed_password)


def create_access_token(username: str, expires_delta: timedelta | None = None) -> str:
    """Cria um token JWT assinado para o usuário autenticado."""
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    payload = {
        "sub": username.strip().lower(),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str) -> str | None:
    """
    Decodifica e valida o token JWT.
    Retorna o username ('sub') se válido ou None se inválido/expirado.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not isinstance(username, str) or not username:
            return None
        return username
    except jwt.PyJWTError:
        return None


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
) -> str:
    """Dependência FastAPI para proteger rotas REST que exigem login."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação ausente.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = verify_access_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username
