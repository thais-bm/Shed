## API local

O backend local mantém a chave privada, cifra e decifra mensagens e salva o
histórico no SQLite em `data/<usuario>_history.db`. O relé não armazena as
mensagens.

Na pasta `client/backend`, sincronize as dependências:

```powershell
uv sync
```

Inicie a API de Alice:

```powershell
$env:SHED_USERNAME = "alice"
uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8001
```

Para testar Bob, abra outro terminal na mesma pasta e use outra porta:

```powershell
$env:SHED_USERNAME = "bob"
uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8002
```

As duas APIs conectam automaticamente ao relé em `ws://127.0.0.1:8000`.

O banco é criado automaticamente pela API local quando uma mensagem
ou histórico é acessado.

Para testar as dependências e a criptografia:

```powershell
uv run pytest
```

Com Alice e Bob em execução, use a documentação interativa:

- Alice: `http://127.0.0.1:8001/docs`
- Bob: `http://127.0.0.1:8002/docs`

No Alice, execute `POST /chat/start/{contato}` com `bob`. Depois de o
handshake terminar, use `GET /chat/safety-number/bob` e
`POST /chat/send/{contato}`. No Bob, consulte `GET /chat/history/alice`.