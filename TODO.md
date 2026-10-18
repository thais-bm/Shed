# 📋 Shed - Roadmap, Kanban & TO-DO List

Este arquivo consolida o estado atual do desenvolvimento do **Shed**, fornecendo uma visão ágil em formato **DONE / DOING / TO-DO** para alinhar toda a equipe sobre o que já está pronto, o que está em andamento e o que falta para finalizar o projeto.

---

## 📊 Kanban Board: DONE / DOING / TO-DO

```text
+-----------------------------------------------+-----------------------------------------------+-----------------------------------------------+
|               DONE (Concluído)                |             DOING (Em Andamento)              |                TO-DO (A Fazer)                |
+-----------------------------------------------+-----------------------------------------------+-----------------------------------------------+
| [x] Handshake ECDH + ECDSA (SECP384R1)        |                                               |                                               |
| [x] Split-Key Password Derivation (HKDF)      |                                               |                                               |
| [x] Cifragem Serpent-CBC + HMAC-SHA256        |                                               |                                               |
| [x] Fixação de Identidade TOFU no SQLite      |                                               |                                               |
| [x] Algoritmo de Safety Number (6x5 dígitos)  |                                               | [ ] Persistência de sessões ECDH no SQLite    |
| [x] Relé Central: Argon2 + JWT + Friends-Only |                                               | [ ] Contador de sequência Anti-Replay         |
| [x] Fila Store-and-Forward (Mensagens Offline)|                                               |                                               |
| [x] Refatoração modular da API Local          |                                               |                                               |
| [x] Auditoria Visual (Client + RelayAuditor)  |                                               |                                               |
| [x] Correção do bug em securityService.js     |                                               |                                               |
| [x] Script start-dev.ps1 + 15 testes pytest   |                                               |                                               |
| [x] Serviços do Frontend React                |                                               |                                               |
| [x] Interface principal conectada à API       |                                               |                                               |
| [x] Componentes visuais de autenticação e chat|                                               |                                               |
| [x] Polling de atualização em tempo real      |                                               |                                               |
+-----------------------------------------------+-----------------------------------------------+-----------------------------------------------+
```

---

## 🟢 1. DONE (Já Concluído, Otimizado e Testado)

### Criptografia & Segurança Central (`client/backend/src/backend/`)
- [x] **Split-Key Password Derivation (`crypto.py`)**:
  - Senha do usuário dividida via `HKDF-SHA256` em `local_storage_key` (nunca sai do dispositivo, cifra a chave privada ECDSA no SQLite) e `relay_login_secret` (enviada ao Relé para autenticação Argon2).
- [x] **ECDHManager & IdentityKeyManager (`crypto.py`)**:
  - Chaves de identidade permanentes `ECDSA` e chaves efêmeras de sessão `ECDH` na curva NIST `SECP384R1`.
  - Assinatura digital `ECDSA-SHA256` em todo handshake `KEY_EXCHANGE`.
- [x] **SerpentProtocol (`serpent_enc.py`)**:
  - Derivação de chaves separadas (`enc_key` e `mac_key` de 256 bits) via `HKDF-SHA256`.
  - Cifragem simétrica Serpent em modo CBC com IV aleatório de 16 bytes e autenticação `HMAC-SHA256` (*Encrypt-then-MAC*).
- [x] **Safety Number (`session.py`)**:
  - Cache da chave pública local em memória e geração determinística de 6 blocos de 5 dígitos para verificação fora de banda.

### Servidor Relé Central (`server/src/server/`)
- [x] **Autenticação Argon2 + JWT (`auth.py`, `__init__.py`)**:
  - Endpoints `/auth/register` e `/auth/login` compatíveis com JSON e formulário OAuth2 do Swagger UI.
  - Validação obrigatória de token JWT no WebSocket `/ws/{username}?token={jwt}`.
- [x] **Grafo de Amizades, Roteamento *Friends-Only* e Fila Offline (`database.py`)**:
  - Busca de usuários (`/users/search`), consulta de chave pública (`/users/{username}/identity-key`) e gestão completa de amigos (`request`, `accept`, `reject`, `DELETE`, `GET /friends`).
  - Bloqueio de pacotes entre não-amigos e armazenamento *Store-and-Forward* (`offline_messages`) para destinatários desconectados.
- [x] **Auditoria Visual do Relé (`server/src/server/audit.py`)**:
  - `RelayAuditor` exibindo no terminal do servidor todas as conexões, trocas de chaves públicas/assinaturas e o raio-X dos pacotes cifrados (`IV` + `Ciphertext` + `HMAC`), comprovando visualmente o modelo *Zero-Knowledge*.

### Cliente Local & Frontend Base (`client/`)
- [x] **Arquitetura Modular e Limpa (`client/backend/src/backend/`)**:
  - Separação clara em `api.py`, `routes.py`, `local_auth.py`, `relay_client.py`, `state.py`, `storage.py` e `audit.py`.
  - Adicionadas rotas proxy completas para amigos (`POST /friends/request/{contato}`, `POST /friends/accept/{contato}`, `POST /friends/reject/{contato}`, `DELETE /friends/{contato}`, `GET /friends`).
  - Resposta enxuta em `POST /chat/send/{contato}` (`{"status": "Mensagem cifrada e enviada."}`) para facilitar o consumo pelo Frontend.
- [x] **Correção do `securityService.js` (`client/frontend/src/services/securityService.js`)**:
  - Corrigida a função `buscarSafetyNumber(contato)` e exportada no `index.js`.
- [x] **Interface React de autenticação, amizades e chat**:
  - Implementados login/registro, busca de usuários, convites, lista de amigos, conversas e modal de Safety Number.
  - Adicionados estados "Pendente" e "Já são amigos" no botão de adicionar amizade.
  - Adicionada barra de scroll estilizada para conversas com muitas mensagens.
- [x] **Script de Inicialização (`start-dev.ps1`) e Testes Automatizados**:
  - `15` testes automatizados passando (`3` no servidor + `12` no cliente local, incluindo teste de comunicação ponta a ponta `test_api_communication.py`).

---

## 🟡 2. DOING (Em Andamento)

- Nenhuma tarefa em andamento no momento.

---

## 🔴 3. TO-DO (Próximas Tarefas para Finalizar o App)

### Fase 3: Evoluções Criptográficas (Pós-MVP)
- [ ] **Persistência de Sessões Simétricas**:
  - Salvar sessões ECDH ativas no SQLite local ou renegociar automaticamente caso o servidor local seja reiniciado.
- [ ] **Proteção contra *Replay Attack***:
  - Incluir número de sequência incremental e timestamp autenticado dentro do payload cifrado.
