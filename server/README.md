## Servidor relé

O relé mantém as conexões WebSocket dos usuários e encaminha cada envelope
JSON para o usuário informado no campo `to`. Ele não acessa nem decifra o
conteúdo das mensagens.

Na pasta `server`, instale as dependências e inicie o relé:

```powershell
uv sync
uv run uvicorn server:app --reload --host 127.0.0.1 --port 8000
```

O cliente local deve ser iniciado separadamente, na pasta `client/backend`,
em outra porta:

```powershell
uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8001
```

Verificações rápidas no navegador:

- Relé: `http://127.0.0.1:8000/health`
- API local: `http://127.0.0.1:8001/health`
- Documentação da API local: `http://127.0.0.1:8001/docs`