# 🎬 Roteiro do Vídeo – Shed (POC de mensageria E2EE)

> **Limite:** 30 min. **Alvo:** 28 min (2 min de folga).
> **Pilar a enfatizar:** **confidencialidade**, demonstrada pelo algoritmo **Serpent-CBC + HMAC-SHA256** e por **todas as evidências de criação e compartilhamento de chaves**.
> **Ideia central (repetir ao longo do vídeo):** *"O relé nunca vê texto em claro, nunca vê a senha e nunca vê uma chave privada."*

---

## 0. Como usar este documento

- 📖 **Material de estudo da equipe:** antes de gravar, leiam [docs/COMO_FUNCIONA.md](docs/COMO_FUNCIONA.md) — lá está a explicação matemática e passo a passo de todo o sistema (equação da curva `SECP384R1`, ECDH, ECDSA, HKDF, Serpent-CBC, HMAC-SHA256, Encrypt-then-MAC e sequência completa de eventos).
- Cada **Parte** tem um apresentador. Troque os nomes na tabela abaixo.
- Cada parte tem: **objetivo**, **tela/preparação**, **passo a passo da demo**, **o que falar** (texto sugerido, adapte com suas palavras), **o que NÃO falar**, **perguntas prováveis da professora** e **transição** para a próxima parte.
- Frases em *itálico* são sugestões de fala. Fale com naturalidade, sem decorar.
- 💡 = dica de gravação. ⚠️ = cuidado.

| Parte | Tempo | Tema | Apresentador |
|---|---|---|---|
| 1 | 0:00–4:00 | Abertura, slide de arquitetura e modelo de ameaça | _______ |
| 2 | 4:00–9:30 | Cadastro e login: **criação das chaves** (Split-Key + identidade ECDSA) | _______ |
| 3 | 9:30–15:30 | Amizades e primeira conversa: **compartilhamento das chaves** (handshake, TOFU, Safety Number) | _______ |
| 4 | 15:30–21:00 | Mensagens: **Serpent + HMAC**, raio-X no relé, anti-replay e mensagens offline | _______ |
| 5 | 21:00–26:00 | Persistência, ataques e defesas (testes), limitações | _______ |
| 6 | 26:00–28:00 | Encerramento | (Apresentador 1) |

---

## 1. Preparação (antes de gravar)

### 1.1 Ambiente limpo
1. Apague os bancos de teste: `server/data/relay.db` e `client/backend/data/*.db`.
2. Na raiz: `.\start-dev.ps1` (sobe relé 8000, cliente 1 em 8001, cliente 2 em 8002, frontends 5173 e 5174).
3. Aguarde as 5 janelas abrirem. Se `npm`/`uv` reclamar, resolva **antes** de gravar.

### 1.2 Organização da tela
- **Esquerda:** navegador com **2 janelas lado a lado** (Alice em `http://127.0.0.1:5173`, Bob em `http://127.0.0.1:5174`).
- **Direita:** 3 terminais empilhados ou em abas grandes: **Relé**, **Cliente 1 (Alice)** e **Cliente 2 (Bob)**.
- 💡 Fonte do terminal em 16–18 pt. Zoom do navegador em 110–125 %. Feche notificações, abas e favoritos.
- 💡 Dê `cls` nos 3 terminais **logo antes** de começar cada parte, assim os logs da parte começam em tela limpa.

### 1.3 Arquivos abertos no editor (para mostrar código)
`client/backend/src/backend/crypto.py`, `session.py`, `serpent_enc.py`, `relay_client.py`, `storage.py` e `server/src/server/__init__.py`.

### 1.4 Ferramenta para abrir o SQLite
Tenha o **DB Browser for SQLite** (ou similar) aberto com `client/backend/data/alice_history.db` para mostrar o cofre. Tabelas úteis: `local_identity`, `established_sessions`, `trusted_identities` e `messages`.

### 1.5 Como ler os terminais (explique isso no vídeo, é um ótimo ponto)
Os logs têm **cabeçalhos de fase** em negrito e **fingerprints** curtos (ex.: `A1B2 C3D4 E5F6 0718`).
- **Fingerprint** = primeiros 8 bytes do SHA-256 de uma chave. Serve para **comparar chaves entre terminais sem mostrar a chave**.
- **Cores:** `[AUTH]` ciano, `[ECDSA]` vermelho, `[ECDH]` azul, `[HANDSHAKE]` amarelo, `[TOFU]` laranja, `[SERPENT]` verde, `[REPLAY]` magenta, `[STORAGE]` amarelo, `[E2EE-REDE]` verde (no relé).
- **Cabeçalhos em ordem cronológica:** `CHAVES 1/4` Split-Key → `2/4` Identidade ECDSA → `3/4` Handshake → `4/4` Segredo compartilhado.

### 1.6 Ensaio obrigatório
Faça um ensaio completo antes. O **mesmo fluxo** foi testado por script (cadastro → amizade → mensagens → reinício do backend → mensagens): funcionou. Mas o ensaio na interface ainda precisa ser feito por vocês.

---

## 2. Regras gerais de fala

**Faça:**
- Sempre diga **o quê**, **por quê** e **como provamos** (evidência na tela).
- Aponte com o mouse para a linha do log que está explicando.
- Use as mesmas palavras em todas as partes: *"chave pública", "chave privada", "chave efêmera", "chave de sessão", "fingerprint"*.
- Admita limitações com naturalidade: isso mostra que entenderam o sistema.

**Evite:**
- Dizer *"é 100% seguro"* ou *"ninguém consegue quebrar"*.
- Ler o código linha a linha. Mostre só o trecho que prova o ponto.
- Dizer *"zero-knowledge"* sem explicar. Prefira: *"o relé não consegue ler o conteúdo"* (ele conhece **metadados**).
- Improvisar correções ao vivo. Se algo travar, corte e regrave o trecho.

---

# PARTE 1 – Abertura, arquitetura e modelo de ameaça (0:00–4:00)

**Objetivo:** contextualizar, apresentar a arquitetura no slide e mostrar contra quem o sistema protege.

**Tela:** slides (2 ou 3). Depois, o README rapidamente, se quiserem.

### Slide 1 – Contexto (≈0:45)
**O que falar:**
- *"O Shed é uma POC de mensageria com criptografia ponta a ponta. A professora pediu que escolhêssemos um algoritmo de criptografia para um sistema de mensageria. A nossa equipe escolheu o Serpent."*
- *"O pilar do projeto é a confidencialidade: só quem conversa consegue ler as mensagens. Nem o servidor."*

### Slide 2 – Arquitetura (≈1:45) ⭐
Desenho sugerido: três caixas em linha.

```
[ Frontend React ] --HTTP--> [ API Local (Python/FastAPI) ] --WebSocket/HTTP--> [ Relé Central (FastAPI) ]
   (navegador)               guarda as CHAVES, cifra e decifra                   só roteia pacotes cifrados
                             SQLite local (cofre + histórico)                    SQLite: contas, amigos, fila offline
```

**O que falar (um componente por vez):**
1. *"O **Frontend React** só mostra a interface. Ele não tem nenhuma chave."*
2. *"A **API Local** roda na máquina de cada usuário. É ela que gera as chaves, assina, cifra e decifra. As chaves privadas ficam aqui, num SQLite local."*
3. *"O **Relé Central** é um servidor intermediário. Ele autentica usuários (Argon2 + JWT), controla quem é amigo de quem, roteia os pacotes e guarda mensagens para quem está offline. Mas ele só vê pacotes **cifrados**."*
4. *"Cada usuário roda a sua própria API Local. Hoje na demo temos duas: Alice (porta 8001) e Bob (porta 8002)."*

💡 Mostre as **setas** do slide indicando por onde passa cada tipo de dado: senha nunca sai da API local; chave privada nunca sai da API local; só **chaves públicas** e **pacotes cifrados** passam pelo relé.

### Slide 3 – Visão Geral do Fluxo Criptográfico (≈1:00) ⭐
> **Dica pedagógica:** nos slides iniciais, mostre o **mapa geral das 4 etapas** em alto nível (1 minuto), e deixe a explicação detalhada (equação da curva, fórmula do HMAC, blocos do Serpent) para o exato momento em que cada apresentador for mostrar o código e o terminal nas Partes 2, 3 e 4. Assim a professora entende o todo logo no início sem ficar cansada com 10 minutos seguidos só de slide!

```
1. CADASTRO (Split-Key + ECDSA)   ──► Senha dividida via HKDF (metade local cifra SQLite, metade vai ao Relé p/ Argon2).
                                      Gera par de Identidade ECDSA (SECP384R1).
2. HANDSHAKE (ECDH + Assinatura)  ──► Troca chaves públicas efêmeras ECDH assinadas com ECDSA + fixação TOFU.
                                      Ambos calculam o mesmo segredo (a·b·G) sem enviá-lo na rede!
3. DERIVAÇÃO (HKDF-SHA256)        ──► Segredo ECDH gera a Chave de Sessão (256b) e se divide em enc_key + mac_key.
4. MENSAGEM (Encrypt-then-MAC)    ──► Empacota {seq, ts, sid, texto} -> cifra com Serpent-CBC (IV 16B) -> assina com HMAC-SHA256.
```

### Slide 4 – Modelo de ameaça (≈1:00)
Tabela no slide:

| Ameaça | Como o Shed se defende |
|---|---|
| Relé curioso lendo mensagens | Cifragem ponta a ponta (Serpent). O relé não tem a chave |
| Relé ou rede vazando senhas | Split-Key: o relé só recebe metade derivada da senha |
| Alguém adulterando um pacote | HMAC-SHA256 (Encrypt-then-MAC) |
| Atacante trocando chaves no handshake (MitM) | Assinatura ECDSA + TOFU + Safety Number |
| Reenvio de pacote capturado (replay) | Contador `seq` + timestamp dentro do payload autenticado |

**O que falar:** *"Para cada ameaça vamos mostrar uma evidência ao longo do vídeo."*

**O que NÃO falar:**
- Não prometa proteger contra *malware no computador do usuário* ou *roubo do dispositivo desbloqueado*. Está fora do escopo.
- Não diga que protegemos metadados (quem fala com quem e quando). O relé **vê** isso.

**Perguntas prováveis:**
- *"Por que ter um relé e não P2P?"* → Simplicidade da POC: o relé resolve descoberta de usuários, usuários offline e NAT, e mesmo assim não lê o conteúdo.
- *"Por que o Serpent?"* → *"Foi uma escolha da equipe: ele nos pareceu interessante."* Complemente com fatos: foi **finalista do concurso do AES**, usa **blocos de 128 bits** e chave de **256 bits**, tem **32 rodadas** (margem de segurança conservadora). Como CBC sozinho não autentica, adicionamos **HMAC-SHA256**.

**Transição:** *"Vamos agora ver como as chaves são criadas, começando pelo cadastro."*

---

# PARTE 2 – Cadastro e login: criação das chaves (4:00–9:30)

**Objetivo:** provar que a senha e as chaves privadas nunca chegam ao relé.

**Preparação:** `cls` nos 3 terminais. Navegador: janela da Alice na tela de cadastro.

### Passo a passo da demo
1. **Cadastrar `alice`** no navegador (senha de exemplo).
2. Olhar o **terminal do Cliente 1 (Alice)**. Aparecem, em ordem:
   - Cabeçalho **`CHAVES 1/4 - SPLIT-KEY DA SENHA (HKDF-SHA256)`**.
   - Cabeçalho **`CHAVES 2/4 - IDENTIDADE PERMANENTE DA CONTA (ECDSA)`**.
   - Logs `[STORAGE]` salvando a identidade no cofre.
3. Olhar o **terminal do Relé**: cabeçalho **`REGISTRO DE CONTA 'alice' NO RELÉ`**.
4. Abrir `crypto.py` e mostrar `PasswordKeyDeriver.derive_master_keys`.
5. Abrir o SQLite `alice_history.db`, tabela `local_identity`: coluna `encrypted_private_key_pem` ilegível.
6. **Cadastrar `bob`** no segundo navegador (rápido, sem explicar de novo).
7. Mostrar o **login** (Sair e entrar de novo com `alice`) e comentar o log `Login validado via Argon2`.

### O que falar

**Split-Key (cabeçalho 1/4):**
- *"A senha do usuário passa por um HKDF-SHA256 e vira duas chaves independentes de 32 bytes."*
- *"A primeira é a `local_storage_key`: nunca sai do dispositivo e protege o cofre local. A segunda é o `relay_login_secret`: é a única coisa enviada ao relé para autenticar."*
- *"Olhem os fingerprints: são diferentes. Não dá para derivar uma metade a partir da outra."* (aponte `D28D…` vs `39E8…`, os valores mudam a cada execução)
- *"Repare que o log diz 'a senha nunca é enviada'. Provamos isso no terminal do relé a seguir."*

**Identidade ECDSA (cabeçalho 2/4):**
- *"Cada conta ganha um par de chaves de identidade na curva **SECP384R1**, de 384 bits. Ela serve para **assinar** e provar quem você é."*
- *"A chave **privada** nunca sai da máquina: é salva no SQLite **cifrada com a `local_storage_key`**. A chave **pública** vai ao relé para os amigos consultarem."*
- Mostre o fingerprint da chave pública e diga *"vamos ver esse mesmo valor no relé"*.

**Terminal do relé (REGISTRO DE CONTA):** ⭐ principal evidência desta parte
- *"O relé recebeu: o `relay_login_secret`, com fingerprint igual ao do cliente, e a chave pública de identidade, também com fingerprint igual."*
- *"Ele guarda um **hash Argon2id** do segredo (parâmetros vistos no log: memória 64 MiB, 3 iterações, paralelismo 4). Mesmo que o banco do relé vaze, não há senha nem chave privada ali."*
- *"O log do relé diz 'NUNCA recebe a senha, a local_storage_key ou chave privada'. E mostramos, comparando fingerprints, que isso é verdade."*

**SQLite (cofre):**
- *"Aqui está a chave privada no banco local. É um blob cifrado, ilegível sem a `local_storage_key`, que só existe se o usuário digitar a senha."*

### O que NÃO falar
- ⚠️ Não diga que a senha é *"impossível de quebrar"*. O Split-Key usa HKDF, que é rápido; ele separa as chaves, mas **não** é um KDF lento. A proteção do cofre depende da **força da senha**. (Se perguntarem: está como melhoria futura trocar por Argon2/scrypt também no lado local.)
- Não mostre a senha de teste real de ninguém.
- Não diga que o JWT é *"criptografia ponta a ponta"*. Ele só autentica a sessão com o relé.

### Perguntas prováveis
- *"Por que dividir a senha em duas?"* → Para o relé conseguir autenticar o usuário sem ter como abrir o cofre local. Se o relé for comprometido, o atacante tem só a metade de login.
- *"Por que ECDSA e não RSA?"* → Chaves menores para o mesmo nível de segurança, assinatura rápida, e a mesma família de curvas do ECDH.
- *"Onde ficam as chaves?"* → Só no SQLite local do usuário, a privada cifrada.
- *"O que acontece se esquecer a senha?"* → Não há recuperação: sem a senha não há `local_storage_key`. É consequência do desenho.

**Transição:** *"Com as contas criadas, vamos ver como dois usuários combinam uma chave de sessão sem nunca trocá-la pela rede."*

---

# PARTE 3 – Amizades e primeira conversa: compartilhamento das chaves (9:30–15:30)

**Objetivo:** mostrar o handshake ECDH assinado com ECDSA, o TOFU e a verificação do Safety Number.

**Preparação:** `cls` nos 3 terminais. Alice e Bob logados, sem conversa.

### Passo a passo da demo
**Bloco A – Amizades (≈1:30)**
1. Alice busca `bob` e envia pedido de amizade. Mostre o estado **"Pendente"**.
2. Bob abre a aba de pedidos e **aceita**. (Mostre também **recusar** em um terceiro usuário, se quiserem demonstrar.)
3. Aponte o log `[FRIENDS]` no relé.

**Bloco B – Handshake (≈3:00) ⭐**
4. Alice abre o chat com `bob` e **envia a primeira mensagem**. O handshake acontece sozinho.
5. Pausar nos terminais e narrar, **nesta ordem**:
   - **Cliente 1 (Alice):** `CHAVES 3/4 - HANDSHAKE COM 'bob'` → par de chaves **efêmeras ECDH** → chave exportada com fingerprint → **assinada com ECDSA** → `KEY_EXCHANGE_INIT enviado`.
   - **Relé:** `INICIANDO troca de chaves` com o **mesmo fingerprint** da chave efêmera.
   - **Cliente 2 (Bob):** `HANDSHAKE RECEBIDO DE 'alice'` → `TOFU`: identidade da Alice **fixada** → assinatura **ECDSA validada**.
   - Bob responde com `KEY_EXCHANGE_REPLY`; o relé mostra `RESPONDENDO` com o fingerprint da chave efêmera do Bob.
   - **Cliente 1** valida a assinatura da Bob e fixa a identidade dela.
   - Ambos mostram `CHAVES 4/4 - SEGREDO COMPARTILHADO` e `SESSÃO E2EE ESTABELECIDA`.
6. **Compare os fingerprints** entre os dois terminais: *chave de sessão*, `enc_key` e `mac_key` devem ser **idênticos**.

**Bloco C – Safety Number (≈1:00)**
7. Alice e Bob abrem o modal do **Safety Number**. Os 6 blocos de 5 dígitos são **iguais**.

### O que falar

**Amizades:**
- *"Só amigos aceitos conversam. O relé só roteia mensagens entre amigos. Nesta POC não há conversa com desconhecidos; é uma decisão de escopo por conta do tempo."*

**Handshake – explique em 5 frases:**
1. *"A Alice gera uma chave **efêmera** ECDH, um par novo só para esta conversa."*
2. *"Ela envia só a parte **pública**, **assinada** com a chave de identidade dela. Esse é o `KEY_EXCHANGE_INIT`."*
3. *"O Bob busca a identidade pública da Alice no relé e **verifica a assinatura**. Se alguém trocasse a chave no meio do caminho, a assinatura não bateria."*
4. *"O Bob responde com a chave efêmera dele, também assinada."*
5. *"Cada lado combina **a sua privada com a pública do outro** (ECDH). O resultado é o mesmo nos dois lados e **nunca trafega pela rede**."*

**Evidência-chave:** *"Olhem os fingerprints. A chave efêmera da Alice é a mesma no cliente e no relé. Mais adiante, a chave de sessão derivada é a mesma nos dois clientes, e o relé nunca a viu."*

**HKDF:** *"O segredo bruto do ECDH não é usado diretamente. Passa por um HKDF-SHA256 e vira uma chave de sessão de 256 bits. Depois, outra derivação cria duas chaves filhas: `enc_key` para cifrar e `mac_key` para autenticar. Chaves separadas evitam reuso."*

**TOFU (Trust On First Use):**
- *"No **primeiro contato**, guardamos a identidade do contato no SQLite. Nas próximas vezes, se a identidade mudar, a conexão é bloqueada, com o alerta de possível MitM."*
- *"O fingerprint fixado é igual ao que o contato mostrou no cadastro."*

**Safety Number:**
- *"O TOFU confia no relé no primeiro contato. Para fechar essa brecha, existe o **Safety Number**: um código de 6 blocos calculado a partir das chaves públicas das duas pontas. Se um atacante estivesse no meio, cada lado veria **um número diferente**. Os dois lados conferem por outro canal, por exemplo por telefone."*
- Mostre os dois modais com o número igual.

### O que NÃO falar
- ⚠️ Não diga que o TOFU *"garante"* a identidade. Ele **protege contra mudanças depois** do primeiro contato; no primeiro contato a confiança está no relé, e o Safety Number cobre isso se for conferido.
- Não diga que o Safety Number é conferido automaticamente. Ele depende do **usuário** comparar.
- Não diga que o segredo ECDH *"é enviado"* ou *"trocado"*. É **calculado** nos dois lados.

### Perguntas prováveis
- *"O que é ECDH?"* → Acordo de chaves Diffie-Hellman em curvas elípticas: cada lado combina a sua privada com a pública do outro e chega ao mesmo segredo.
- *"Por que chaves efêmeras?"* → Cada conversa usa um par novo, então a chave de sessão não depende da chave de identidade permanente.
- *"Por que assinar com ECDSA se já tem ECDH?"* → ECDH sozinho **não autentica**; sem assinatura, um intermediário poderia se passar pelo outro (MitM).
- *"E se o relé fosse malicioso?"* → Ele pode trocar chaves no **primeiro** contato, mas o Safety Number revelaria o ataque. Depois do primeiro contato, o TOFU bloquearia a troca.
- *"Por que o handshake acontece uma vez só?"* → A sessão é guardada cifrada no SQLite e restaurada no login. Mostramos isso na Parte 5.

**Transição:** *"Com a chave de sessão pronta, vamos ver como as mensagens são cifradas."*

---

# PARTE 4 – Mensagens: Serpent + HMAC, raio-X no relé, anti-replay e offline (15:30–21:00)

**Objetivo:** mostrar o algoritmo escolhido em ação e provar que o relé só vê dados cifrados.

**Preparação:** `cls` nos 3 terminais. Arquivo `serpent_enc.py` aberto.

### Passo a passo da demo
**Bloco A – Algoritmo (≈1:30), com o código**
1. Abra `serpent_enc.py`. Mostre `__init__` (HKDF → `enc_key` e `mac_key`), `encrypt_message` e `decrypt_message`.

**Bloco B – Envio e recebimento (≈2:00) ⭐**
2. Alice envia: **`Olá Bob, esta mensagem é secreta!`**
3. **Terminal do Cliente 1:** `[REPLAY]` (cabeçalho `seq=…`) e `[SERPENT] CIFRANDO…` com IV, cifra, HMAC e tamanho total do pacote.
4. **Terminal do Relé:** `E2EE-REDE: Mensagem cifrada atravessando o Servidor Relé!` Mostre `Texto limpo no Relé: [ILEGÍVEL…]`.
5. **Terminal do Cliente 2 (Bob):** `DECIFRANDO`, `HMAC VÁLIDO…ANTES de decifrar`, `Mensagem decifrada`, `[REPLAY] seq=… ACEITO`.
6. No navegador do Bob, a mensagem aparece. Bob responde (mostre o caminho de volta).

**Bloco C – Mensagem offline (≈1:30)**
7. Bob clica em **Sair** (logout).
8. Alice envia 2 mensagens. No relé aparece que Bob está **OFFLINE** e que o pacote foi guardado na fila.
9. Bob **entra de novo**. O relé mostra `Descarregando fila Store-and-Forward` e as mensagens chegam.

### O que falar

**Algoritmo:**
- *"A cifra é o **Serpent em modo CBC**: bloco de 128 bits, chave de 256 bits, IV aleatório de 16 bytes **a cada mensagem**."*
- *"Usamos **Encrypt-then-MAC**: primeiro cifra, depois calcula um **HMAC-SHA256** sobre `IV + cifra`. O destinatário verifica o HMAC **antes de decifrar**. Assim, um pacote adulterado é descartado sem sequer tocar na cifra."*
- *"Duas chaves diferentes, derivadas por HKDF: uma só para cifrar, outra só para autenticar."*
- Mostre o formato: **`IV (16 B) ‖ Cifra (N × 16 B) ‖ HMAC (32 B)`**.

**Cabeçalho anti-replay:**
- *"Antes de cifrar, o texto é embrulhado com um cabeçalho: `seq` (contador), `ts` (timestamp) e `sid` (identificador do remetente). Isso fica **dentro** da cifra e protegido pelo HMAC."*
- *"Se alguém capturar um pacote e reenviar, o `seq` já foi usado e o destinatário rejeita. O `sid` impede que o pacote seja devolvido ao próprio remetente."*

**Raio-X no relé:** ⭐ evidência principal da confidencialidade
- *"Aqui está o que o relé enxerga: um IV, uma cifra e um HMAC. A linha final diz que o texto limpo é ilegível para ele, e é verdade: ele não tem a chave de sessão."*
- *"O relé conhece **metadados**: quem fala com quem, quando e o tamanho do pacote. Isso não protegemos nesta POC."*

**Offline:**
- *"Se o destinatário está offline, o relé guarda o **pacote já cifrado** (Store-and-Forward). Quando ele volta, recebe e decifra. A fila nunca contém texto limpo."*

### O que NÃO falar
- ⚠️ Não diga que o histórico do chat é cifrado no disco. **Não é**: as mensagens ficam em texto claro no SQLite local (tabela `messages`). A cifragem protege o **tráfego e o relé**. Se perguntarem: é uma limitação conhecida, uma melhoria futura seria cifrar o histórico com a `local_storage_key`.
- ⚠️ Não esconda que os logs de auditoria mostram texto decifrado no terminal do cliente. Diga: *"é um modo de auditoria da demonstração; em produção seria desligado."*
- Não diga que o CBC *"garante integridade"*. Quem garante é o **HMAC**.
- Não diga que o Serpent é *"mais seguro que o AES"*. Diga que é um **finalista do concurso do AES**, com margem de segurança conservadora.

### Perguntas prováveis
- *"Por que CBC e não GCM?"* → A biblioteca de Serpent que usamos oferece o modo CBC, que **não autentica** por si só. Por isso combinamos com HMAC-SHA256 (Encrypt-then-MAC), um padrão seguro. GCM seria uma alternativa futura.
- *"Por que um IV aleatório por mensagem?"* → No CBC, repetir o IV com a mesma chave vaza padrões. Um IV novo por mensagem evita isso.
- *"Por que verificar o HMAC antes de decifrar?"* → Evita ataques em que o atacante manda lixo para observar o comportamento da decifragem.
- *"O que acontece se alguém alterar 1 bit?"* → O HMAC falha, o pacote é descartado e o log mostra `FALHA DE INTEGRIDADE` (mostramos no teste da Parte 5).

**Transição:** *"Agora vamos ver o que acontece quando reiniciamos o sistema e quando alguém tenta atacar."*

---

# PARTE 5 – Persistência, ataques e limitações (21:00–26:00)

**Objetivo:** provar que o handshake é único, que o sistema resiste aos ataques previstos e ser honestos sobre os limites.

**Preparação:** terminal extra em `client/backend` com o venv ativo. Ou use `.\.venv\Scripts\python -m pytest ...`.

### Passo a passo da demo
**Bloco A – Sessão persistida (≈1:30)**
1. No SQLite, mostre `established_sessions`: coluna `encrypted_session_key` **ilegível**, e `send_seq`/`recv_seq` com os contadores.
2. Feche o terminal do **Cliente 1 (Alice)** e suba de novo (`uv run uvicorn backend.api:app --host 127.0.0.1 --port 8001`). Faça **login** da Alice.
3. Note no log: `1 sessão(ões) E2EE restaurada(s) do cofre local (sem necessidade de novo handshake)`.
4. Envie mensagens nos dois sentidos: funcionam **sem novo handshake**. O Safety Number é o mesmo.

**Bloco B – Ataques com os testes (≈2:30)**
Rode, mostrando só a parte relevante da saída:

| Ataque | Comando (pasta `client/backend`) | O que mostrar |
|---|---|---|
| MitM sem verificação | `.\.venv\Scripts\python -m pytest -s tests/test_session.py` | O atacante lê e altera, mas o **Safety Number diverge** |
| MitM com identidade | `.\.venv\Scripts\python -m pytest -s tests/test_identity_and_split_key.py` | Assinatura falsa **recusada** |
| Adulteração | `.\.venv\Scripts\python -m pytest -s tests/test_cyphertext.py` | HMAC rejeita 1 bit alterado |
| Replay | `.\.venv\Scripts\python -m pytest -v tests/test_replay_protection.py` | Replay, fora de ordem, reflexão e timestamp futuro **rejeitados** |
| Tudo | `.\.venv\Scripts\python -m pytest -q` | **21 testes** passando no cliente (+3 no servidor) |

**Bloco C – Limitações (≈1:00)** (leia/mostre em slide)

### O que falar

**Persistência:**
- *"A sessão E2EE é salva no SQLite **cifrada com a `local_storage_key`**. Ao reiniciar e logar, ela é restaurada. O handshake acontece **uma única vez** por par de amigos."*
- *"Os contadores anti-replay também são salvos. Assim, um replay depois de reiniciar continua sendo barrado."*

**Ataques:**
- *"No teste de MitM sem verificação, o atacante consegue ler e até adulterar a mensagem. É de propósito: mostra por que existem a assinatura e o Safety Number. A defesa é que os números divergem."*
- *"Com a assinatura ECDSA, o handshake falso é recusado antes de qualquer sessão ser criada."*
- *"No replay, o mesmo pacote só é aceito uma vez."*

**Limitações (seja direto, é pontos a favor):**
- *Sem forward secrecy contínuo: a chave de sessão não é renovada. Melhoria futura: rotação periódica ou ratchet.*
- *Anti-replay com sequência estritamente crescente: não tolera entrega fora de ordem; uma janela deslizante resolveria.*
- *O Split-Key usa HKDF: a proteção do cofre depende da força da senha. Melhoria: KDF lento (Argon2/scrypt) no cliente.*
- *O histórico local fica em texto claro no SQLite.*
- *O relé conhece metadados (quem, quando, tamanho).*
- *Só conversa entre amigos aceitos: decisão de escopo da POC.*
- *O Safety Number precisa ser conferido pelos usuários.*

### O que NÃO falar
- Não diga que persistir a chave de sessão é *"mais seguro"*. É uma troca: **conveniência** (um handshake só) versus **menos renovação de chave**. Declare isso como limitação.
- Não minimize o MitM: diga que a **verificação do Safety Number é necessária**.

### Perguntas prováveis
- *"Por que não refazer o handshake sempre?"* → Seria mais seguro (forward secrecy), mas pioraria a experiência; ficou como melhoria futura.
- *"E se o dispositivo for roubado?"* → Sem a senha, as chaves privadas e a sessão ficam cifradas. Com o dispositivo **desbloqueado**, não há proteção. Fora do escopo.

**Transição:** *"Para fechar, um resumo do que provamos."*

---

# PARTE 6 – Encerramento (26:00–28:00)

**Slide final – resumo (≈1:15):**

| Pergunta | Evidência |
|---|---|
| O relé lê as mensagens? | Não: raio-X mostra só IV + cifra + HMAC |
| O relé tem a senha ou chaves privadas? | Não: só recebe a metade `relay_login_secret` e chaves públicas (fingerprints iguais) |
| Como as chaves foram criadas? | Split-Key (HKDF) e ECDSA SECP384R1 |
| Como foram compartilhadas? | ECDH efêmero assinado com ECDSA, com TOFU e Safety Number |
| Como foram protegidas no disco? | Privada e sessão cifradas com `local_storage_key` |
| E ataques? | HMAC (adulteração), ECDSA/Safety Number (MitM), `seq`/`ts`/`sid` (replay) |

**O que falar:**
- *"Mostramos todas as funcionalidades: cadastro, login, amizades, chat, Safety Number, mensagens offline, restauração de sessão e proteções."*
- *"Reforçando o pilar: a confidencialidade vem do Serpent-CBC com HMAC, e a confiança nas chaves vem de ECDH assinado com ECDSA, TOFU e Safety Number."*
- *"Conhecemos as limitações e listamos melhorias futuras. Obrigado!"*

---

## 3. Checklist final de evidências (marque durante a revisão do vídeo)

**Criação das chaves**
- [ ] Split-Key no terminal (`CHAVES 1/4`) com fingerprints diferentes para a chave local e a de login
- [ ] Identidade ECDSA (`CHAVES 2/4`) com fingerprint da pública
- [ ] Chave privada **cifrada** no SQLite (`local_identity`)
- [ ] Registro no relé (fingerprints iguais aos do cliente) com hash Argon2

**Compartilhamento das chaves**
- [ ] Chave efêmera ECDH com **fingerprint igual** no cliente e no relé
- [ ] Assinatura ECDSA gerada e **validada**
- [ ] TOFU fixando a identidade (com fingerprint)
- [ ] `CHAVES 4/4`: chave de sessão com **fingerprint igual** nos dois clientes; `enc_key` e `mac_key` iguais
- [ ] Safety Number **igual** nos dois lados
- [ ] Sessão salva cifrada e restaurada após reinício (sem novo handshake)

**Confidencialidade**
- [ ] Código do Serpent-CBC + HMAC (Encrypt-then-MAC)
- [ ] Pacote no relé **sem texto legível**
- [ ] HMAC verificado **antes** de decifrar
- [ ] Mensagem offline guardada **cifrada** e entregue
- [ ] Ataques: MitM, adulteração e replay (testes)

**Funcionalidades (todas)**
- [ ] Cadastro / Login / Sair
- [ ] Busca de usuários
- [ ] Pedido de amizade, **pendente**, aceitar e recusar
- [ ] Chat com handshake automático
- [ ] Modal do Safety Number
- [ ] Mensagens offline
- [ ] Tema claro/escuro e scroll de conversas

> ℹ️ A remoção de amigo existe na API (`DELETE /friends/{contato}`), mas **não tem botão na interface**. Se quiserem mostrar, usem o Swagger do cliente em `http://127.0.0.1:8001/docs`. Ao remover, a sessão E2EE também é apagada.

---

## 4. Plano B (se algo falhar durante a gravação)
- **Relé não sobe:** verifique a porta 8000 livre e rode o `uv sync` do servidor.
- **Handshake não completa:** confirme que os dois usuários são amigos aceitos e que os dois estão logados.
- **Mensagem não chega:** confira nos terminais se aparece `Conectado ao Relé Central`. Se não, faça Sair/Entrar.
- **Reinício do backend mudou a sessão:** apague os bancos e recomece a gravação da parte.
- **Último recurso:** mostre a saída do `pytest` com os testes passando e use o log do ensaio.

---

## 5. Glossário rápido (para consulta durante as perguntas)

| Termo | Explicação curta |
|---|---|
| **Split-Key** | A senha vira duas chaves: uma local (cofre) e uma para o relé (login) |
| **HKDF** | Função que deriva chaves a partir de um segredo; aqui, SHA-256 |
| **ECDSA** | Assinatura digital com curvas elípticas (identidade) |
| **ECDH** | Acordo de chaves com curvas elípticas (chave de sessão) |
| **SECP384R1** | Curva NIST de 384 bits usada em ECDSA e ECDH |
| **Chave efêmera** | Par ECDH criado só para uma sessão |
| **TOFU** | Fixa a identidade no primeiro contato e bloqueia mudanças depois |
| **Safety Number** | Código para conferir, por outro canal, que não há MitM |
| **Serpent-CBC** | Cifra de bloco Serpent (128 bits, chave de 256) em encadeamento de blocos |
| **HMAC-SHA256** | Lacre de integridade e autenticidade do pacote |
| **Encrypt-then-MAC** | Cifra primeiro, autentica depois; verifica antes de decifrar |
| **Argon2id** | Hash de senha lento, usado pelo relé |
| **JWT** | Token de sessão com o relé (autenticação, não é cifragem de mensagens) |
| **Store-and-Forward** | Relé guarda o pacote cifrado até o destinatário voltar |
| **Replay** | Reenvio de um pacote capturado |
| **Fingerprint** | 8 bytes do SHA-256 de uma chave, para comparar sem mostrá-la |
| **Metadados** | Quem fala com quem, quando e quanto; o relé os conhece |
