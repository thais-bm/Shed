# 📋 Shed - Roadmap, Kanban & TO-DO List

Este arquivo consolida o estado atual do desenvolvimento do **Shed**, fornecendo uma visão ágil em formato **DO / DONE / DOING** e o detalhamento técnico das próximas tarefas necessárias para completar o projeto.

---

## 📊 Kanban Board: DO / DONE / DOING

```
+-----------------------------------------------------------------------------------------------------------------+
|               DONE (Concluído)              |            DOING (Em Andamento)           |          TO-DO (A Fazer)          |
+-----------------------------------------------------------------------------------------------------------------+
| [x] Handshake ECDH (SECP384R1)              | [ ] Correção do bug em securityService.js | [ ] Interface gráfica de Chat UI  |
| [x] Derivação de chaves HKDF-SHA256         | [ ] Integração do Frontend com as APIs   | [ ] Push em tempo real (SSE/WS)   |
| [x] Cifragem Serpent CBC + PKCS#7           | [ ] Testes manuais integrados Alice/Bob   | [ ] Persistência de sessões ECDH  |
| [x] HMAC-SHA256 (Encrypt-then-MAC)          |                                           | [ ] Proteção contra Replay Attack |
| [x] Algoritmo e teste de Safety Number      |                                           | [ ] Script único de inicialização |
| [x] Assinatura ECDSA + TOFU no Handshake    |                                           |                                   |
| [x] Split-Key Password Derivation (HKDF)    |                                           |                                   |
| [x] Autenticação Argon2 + JWT no Relé       |                                           |                                   |
| [x] Roteamento Friends-Only e Fila Offline  |                                           |                                   |
| [x] Auth & Friends Proxy na API Local       |                                           |                                   |
| [x] Bateria de testes unitários (14 testes) |                                           |                                   |
+-----------------------------------------------------------------------------------------------------------------+
```

---

## 🟢 1. DONE (Já Concluído e Testado)

### Criptografia & Segurança Central
- [x] **ECDHManager (`client/backend/src/backend/crypto.py`)**:
  - Geração de par de chaves assimétricas na curva NIST SECP384R1.
  - Exportação e importação de chaves públicas em formato PEM padrão.
  - Derivação de segredo compartilhado bruto e HKDF-SHA256 com contexto `shed-session-key`.
- [x] **SerpentProtocol (`client/backend/src/backend/serpent_enc.py`)**:
  - Derivação de duas chaves independentes de 256 bits via HKDF (`enc_key` para cifra e `mac_key` para assinatura).
  - Cifragem simétrica Serpent em modo CBC com IV aleatório de 16 bytes.
  - Autenticação de integridade via HMAC-SHA256 em arquitetura Encrypt-then-MAC (`[IV] + [Ciphertext] + [MAC]`).
  - Verificação rigorosa do HMAC antes de qualquer tentativa de decifragem.
- [x] **Safety Number (`client/backend/src/backend/session.py`)**:
  - Ordenação lexicográfica determinística das chaves públicas de ambos os pares.
  - Formatação em 6 blocos numéricos legíveis de 5 dígitos para checagem out-of-band.
- [x] **Bateria de Testes (`client/backend/tests/`)**:
  - `test_chat.py`: Comunicação bidirecional limpa entre Alice e Bob.
  - `test_crypto.py`: Validação de coincidência matemática do segredo compartilhado.
  - `test_cyphertext.py`: Rejeição imediata de pacotes adulterados por alteração de bit.
  - `test_serpent_enc.py`: Caminho feliz, simulação de hacker e rejeição de pacotes truncados.
  - `test_session.py`: Fluxo completo de sessão e teste de ataque MitM comprovando divergência do Safety Number.

### Servidor Relé (Protótipo)
- [x] **FastAPI WebSocket Relay (`server/src/server/__init__.py`)**:
  - Endpoint `/ws/{username}` para manter conexões ativas em memória.
  - Roteamento transparente de envelopes JSON (`from`, `to`, `type`, `payload`).
  - Desconexão automática de sessões duplicadas do mesmo usuário.

### Cliente Local & Armazenamento
- [x] **API Local (`client/backend/src/backend/api.py`)**:
  - Daemon local que conecta ao relé via WebSocket em segundo plano (`listen_to_relay`).
  - Endpoints REST `/chat/start/{contato}`, `/chat/send/{contato}`, `/chat/history/{contato}` e `/chat/safety-number/{contato}`.
- [x] **Banco Local (`client/backend/src/backend/storage.py`)**:
  - SQLite individual por usuário (`data/<username>_history.db`).
  - Registro de mensagens enviadas e recebidas com timestamp.
- [x] **Auditoria Visual (`client/backend/src/backend/audit.py`)**:
  - Terminal interativo com logs coloridos por módulo (`[ECDH]`, `[SERPENT]`, `[STORAGE]`, `[API]`).

---

## 🟡 2. DOING (Em Andamento)

- [ ] **Correção do Serviço de Segurança do Frontend**:
  - Corrigir `client/frontend/src/services/securityService.js`, que atualmente replica `buscarHistorico` por engano em vez de exportar a função `buscarSafetyNumber(contato)`.
- [ ] **Estruturação da Camada de Serviços do Frontend**:
  - Os módulos de serviço (`apiClient.js`, `chatService.js`, `historyService.js`) foram criados recentemente e precisam de conexão com componentes visuais de tela.
- [ ] **Validação E2E entre Alice e Bob**:
  - Testes manuais via documentação interativa Swagger (`http://127.0.0.1:8001/docs` e `:8002/docs`).

---

## 🔴 3. TO-DO (Priorizado por Fases)

### Fase 1: Interface Gráfica (Frontend React)
- [ ] **Substituir Template Padrão do Vite (`client/frontend/src/App.jsx`)**:
  - Remover código do contador e botões padrão.
- [ ] **Componente de Contatos e Início de Conversa**:
  - Campo para digitar o nome do contato desejado e botão "Iniciar Chat Seguro".
  - Lista de conversas recentes salvas localmente.
- [ ] **Componente de Janela de Chat**:
  - Exibição de mensagens em balões (diferenciando remetente e destinatário).
  - Campo de entrada de texto e botão de envio com tecla Enter.
- [ ] **Modal / Badge do Safety Number**:
  - Botão de "Segurança" no topo do chat para exibir os 6 blocos numéricos do contato ativo.
  - Indicador visual de confirmação da identidade do par.
- [ ] **Barra de Status da Conexão**:
  - Indicador de status da conexão com a API local (`:8001`) e com o Servidor Relé.

### Fase 2: Atualização em Tempo Real (Local API ➡️ React)
- [ ] **Notificação de Novas Mensagens**:
  - Atualmente a API salva no SQLite, mas o React não recebe evento push imediato.
  - Implementar Server-Sent Events (SSE) em `GET /chat/events` ou WebSocket local na porta `8001` para avisar a tela quando uma mensagem chegar.

### Fase 3: Autenticação & Gestão de Amigos no Servidor Relé ✅
*(Conforme especificado em [`docs/AUTHENTICATION_AND_DISCOVERY.md`](docs/AUTHENTICATION_AND_DISCOVERY.md))*
- [x] **Banco de Dados no Servidor (`server/src/server/database.py`)**:
  - Tabelas SQLite criadas: `users`, `friendships`, `offline_messages`.
- [x] **Endpoints de Autenticação (`server/src/server/auth.py` & `__init__.py`)**:
  - `POST /auth/register`: Cadastro com hash seguro de senha (Argon2) e registro de Chave de Identidade.
  - `POST /auth/login`: Validação de credenciais e emissão de JWT.
- [x] **Proteção do WebSocket & Roteamento Friends-Only**:
  - Validação obrigatória de `?token={access_token}` no `/ws/{username}` para usuários registrados, impedindo roubo de identidade.
  - Bloqueio automático de pacotes de handshake/chat caso remetente e destinatário não sejam amigos aceitos (`are_friends`).
- [x] **CRUD de Descoberta e Amigos**:
  - `GET /users/search?q={query}` & `GET /users/{username}/identity-key`: Busca de usuários e consulta de chave pública de identidade.
  - `POST /friends/request/{username}`: Envio de solicitação.
  - `POST /friends/accept/{username}` & `POST /friends/reject/{username}`: Aceite/recusa de amizade.
  - `DELETE /friends/{username}`: Remoção de amizade.
  - `GET /friends`: Listagem de amigos confirmados e solicitações pendentes.
- [x] **Split-Key Derivation + Assinatura ECDSA + TOFU no Cliente Local (`client/backend`)**:
  - Derivação dividida via HKDF (`local_storage_key` retida no dispositivo + `relay_login_secret` enviada ao relé).
  - Geração de Chave de Identidade ECDSA (`SECP384R1`), cofre local cifrado no SQLite, assinatura digital do handshake ECDH e verificação TOFU (`trusted_identities`).
  - Rotas de registro, login e gestão de amigos integradas em `client/backend/src/backend/api.py`.

### Fase 4: Confiabilidade & Mensagens Offline
- [x] **Fila Store-and-Forward (`server/src/server/database.py`)**:
  - Se Bob estiver desconectado quando Alice enviar uma mensagem, o relé retém o envelope JSON cifrado no banco e entrega assim que Bob autenticar no WebSocket.
- [ ] **Recibos de Entrega / Erro**:
  - Avisar o remetente caso o destinatário não exista ou caso o pacote tenha sido enfileirado offline.

### Fase 5: Robustez Criptográfica & Persistência de Sessões
- [ ] **Persistência de Sessões Locais**:
  - `sessoes_ativas` atualmente fica apenas em memória RAM. Se o backend reiniciar, a chave da sessão é perdida.
  - Implementar renegociação automática de handshake caso receba mensagem e não haja sessão ativa.
- [ ] **Proteção contra Replay Attack**:
  - Incluir número de sequência incremental e timestamp autenticado dentro do payload cifrado.
- [ ] **Criptografia do Banco de Dados Local**:
  - Proteger `data/<username>_history.db` com SQLCipher ou criptografia local em repouso.
- [ ] **Chave Ratchet / Perfect Forward Secrecy (PFS)**:
  - Evoluir o protocolo para rotacionar a chave simétrica a cada mensagem (Double Ratchet), garantindo que mensagens antigas permaneçam seguras mesmo em caso de vazamento da chave atual.

### Fase 6: Experiência do Desenvolvedor (DX) & Automação
- [ ] **Script de Inicialização Unificada (`start-dev.ps1`)**:
  - Script PowerShell para subir com um clique: Relé (porta 8000), Alice (8001), Bob (8002) e Frontend Vite (5173).
- [ ] **Configuração Docker / Docker Compose**:
  - Arquivo `docker-compose.yml` para implantação simplificada do servidor relé.
