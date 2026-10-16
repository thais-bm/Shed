## API local

O backend local mantém a chave privada de identidade cifrada, realiza o handshake ECDH assinado com ECDSA, cifra e decifra mensagens com Serpent + HMAC e salva o histórico no SQLite em `data/<usuario>_history.db`.

Na pasta `client/backend`, sincronize as dependências:

```powershell
uv sync
```

Inicie a primeira instância local (ex: porta 8001):

```powershell
uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8001
```

Para testar um segundo usuário na mesma máquina, abra outro terminal na mesma pasta e use outra porta (ex: porta 8002):

```powershell
uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8002
```

Para testar as dependências e a criptografia:

```powershell
uv run pytest
```

Com as duas instâncias e o servidor relé (`:8000`) em execução, use a documentação interativa:

- Instância 1: `http://127.0.0.1:8001/docs`
- Instância 2: `http://127.0.0.1:8002/docs`

### Fluxo de Uso no Swagger UI (`/docs`)
1. Crie a conta em `POST /auth/register` (informando `username` e `password`).
2. Clique no botão verde **Authorize** no topo da página e faça login com seu `username` e `password` (`OAuth2PasswordBearer`).
3. Envie e aceite convite de amizade em `/friends/request/{contato}` e `/friends/accept/{contato}`.
4. Inicie o handshake seguro em `POST /chat/start/{contato}`, confira o código em `GET /chat/safety-number/{contato}` e envie mensagens em `POST /chat/send/{contato}`.