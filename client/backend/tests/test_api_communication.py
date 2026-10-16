# client/backend/tests/test_api_communication.py
"""
Teste de ponta a ponta (E2E) da comunicação via API (Alice <-> Relé <-> Bob).
Demonstra como as rotas HTTP da API Local (`routes.py`) conversam com o Relé
e trocam envelopes WebSocket assinados (ECDSA) e cifrados (Serpent-CBC + HMAC).
"""

import json
from fastapi.testclient import TestClient

from backend.api import app
from backend.audit import SecurityAuditor
from backend.crypto import IdentityKeyManager, PasswordKeyDeriver
from backend.session import SecureSession
from backend.state import state
from backend.storage import LocalStorage


class FakeRelayWebSocket:
    """
    Simula o canal WebSocket do Servidor Relé em memória para inspecionar
    exatamente cada envelope JSON que a API Local envia na rede.
    """

    def __init__(self) -> None:
        self.sent_envelopes: list[dict] = []

    async def send(self, raw_json: str) -> None:
        envelope = json.loads(raw_json)
        self.sent_envelopes.append(envelope)
        SecurityAuditor.log_step(
            "API",
            f"[REDE -> RELÉ] Envelope '{envelope['type']}' enviado de '{envelope['from']}' para '{envelope['to']}'",
        )

    async def close(self) -> None:
        pass


def test_fluxo_completo_de_comunicacao_da_api(tmp_path, monkeypatch):
    """
    Simula a conversa completa usando as rotas HTTP da API Local de Alice (`TestClient(app)`)
    comunicando com Bob através de envelopes de rede:
      1. Alice autentica e gera sua Chave de Identidade ECDSA (Split-Key).
      2. Alice chama `POST /chat/start/bob` -> API gera envelope `KEY_EXCHANGE_INIT` assinado.
      3. Bob recebe o envelope, valida a assinatura ECDSA de Alice (TOFU) e devolve `KEY_EXCHANGE_REPLY`.
      4. Alice confere `GET /chat/safety-number/bob`.
      5. Alice chama `POST /chat/send/bob` -> API cifra com Serpent + HMAC e envia `CHAT_MESSAGE`.
      6. Bob decifra o pacote da rede e responde para Alice.
      7. Alice consulta `GET /chat/history/bob` e vê toda a conversa salva no SQLite!
    """
    print("\n")
    SecurityAuditor.log_step("TESTE", "=== INICIANDO TESTE DE COMUNICAÇÃO DA API (ALICE <-> RELÉ <-> BOB) ===")

    # Isola o banco de dados SQLite em uma pasta temporária para o teste
    monkeypatch.chdir(tmp_path)

    client = TestClient(app)
    fake_ws = FakeRelayWebSocket()

    # =========================================================================
    # 1. Preparação das Identidades de Alice (API Local) e Bob (Par Remoto)
    # =========================================================================
    id_mgr = IdentityKeyManager()

    # Alice (configurada no estado da API Local)
    alice_local_key, _ = PasswordKeyDeriver.derive_master_keys("alice", "SenhaAlice123")
    alice_id_priv, alice_id_pub = id_mgr.generate_identity_key_pair()
    alice_id_pub_pem = id_mgr.export_public_key(alice_id_pub).decode("utf-8")

    state.username = "alice"
    state.relay_jwt_token = "fake-jwt-token-alice"
    state.identity_private_key = alice_id_priv
    state.identity_public_key_pem = alice_id_pub_pem
    state.relay_websocket = fake_ws
    state.active_sessions.clear()

    # Bob (par remoto com sua própria Chave de Identidade e Sessão)
    bob_id_priv, bob_id_pub = id_mgr.generate_identity_key_pair()
    bob_id_pub_pem = id_mgr.export_public_key(bob_id_pub)
    bob_session = SecureSession()

    # =========================================================================
    # 2. Alice inicia o chat via API: POST /chat/start/bob
    # =========================================================================
    SecurityAuditor.log_step("TESTE", "Passo 1: Alice chama POST /chat/start/bob na API Local...")
    res_start = client.post("/chat/start/bob")
    assert res_start.status_code == 200
    assert res_start.json()["signed"] is True

    # Verifica o envelope que a API de Alice jogou no WebSocket do Relé
    init_envelope = fake_ws.sent_envelopes[-1]
    assert init_envelope["type"] == "KEY_EXCHANGE_INIT"
    assert init_envelope["from"] == "alice"
    assert init_envelope["to"] == "bob"
    assert "public_key" in init_envelope
    assert "signature" in init_envelope

    # =========================================================================
    # 3. Bob recebe KEY_EXCHANGE_INIT do Relé, valida ECDSA e responde
    # =========================================================================
    SecurityAuditor.log_step("TESTE", "Passo 2: Bob recebe KEY_EXCHANGE_INIT, valida assinatura ECDSA e responde...")
    bob_session.establish_session(
        peer_public_key_pem=init_envelope["public_key"].encode("utf-8"),
        signature=bytes.fromhex(init_envelope["signature"]),
        peer_identity_public_key_pem=alice_id_pub_pem.encode("utf-8"),
    )
    assert bob_session.is_established

    # Bob gera sua resposta assinada (KEY_EXCHANGE_REPLY) e entrega para a sessão de Alice
    bob_eph_pub_pem, bob_sig = bob_session.get_signed_public_key(bob_id_priv)
    alice_session = state.active_sessions["bob"]
    alice_session.establish_session(
        peer_public_key_pem=bob_eph_pub_pem,
        signature=bob_sig,
        peer_identity_public_key_pem=bob_id_pub_pem,
    )
    assert alice_session.is_established

    # =========================================================================
    # 4. Alice consulta o Safety Number via API: GET /chat/safety-number/bob
    # =========================================================================
    SecurityAuditor.log_step("TESTE", "Passo 3: Alice consulta GET /chat/safety-number/bob...")
    res_safety = client.get("/chat/safety-number/bob")
    assert res_safety.status_code == 200
    alice_safety_number = res_safety.json()["safety_number"]
    assert alice_safety_number == bob_session.get_safety_number()
    SecurityAuditor.log_step("TESTE", f"Safety Number verificado: {alice_safety_number}")

    # =========================================================================
    # 5. Alice envia uma mensagem via API: POST /chat/send/bob
    # =========================================================================
    SecurityAuditor.log_step("TESTE", "Passo 4: Alice chama POST /chat/send/bob com texto em claro...")
    texto_alice = "Olá Bob! Testando o envio pela rota HTTP da API Local!"
    res_send = client.post("/chat/send/bob", json={"text": texto_alice})
    assert res_send.status_code == 200

    # Inspeciona o pacote CHAT_MESSAGE que saiu pelo WebSocket para o Relé
    chat_envelope = fake_ws.sent_envelopes[-1]
    assert chat_envelope["type"] == "CHAT_MESSAGE"
    assert chat_envelope["from"] == "alice"
    assert chat_envelope["to"] == "bob"

    # Garante que o texto limpo NÃO está visível no envelope da rede!
    assert texto_alice not in chat_envelope["payload"]

    # Bob recebe o payload hexadecimal do Relé e decifra com Serpent + HMAC
    payload_cifrado = bytes.fromhex(chat_envelope["payload"])
    texto_decifrado_por_bob = bob_session.decrypt(payload_cifrado)
    assert texto_decifrado_por_bob == texto_alice

    # =========================================================================
    # 6. Bob envia uma resposta cifrada e Alice consulta GET /chat/history/bob
    # =========================================================================
    SecurityAuditor.log_step("TESTE", "Passo 5: Bob responde cifrado e Alice lê GET /chat/history/bob...")
    resposta_bob = "Recebido alto e claro, Alice! Tudo cifrado com Serpent!"
    pacote_bob = bob_session.encrypt(resposta_bob)

    # Alice decifra e salva no banco local (como faz o listener do WebSocket)
    texto_recebido_alice = alice_session.decrypt(pacote_bob)
    LocalStorage("alice").save_message(contact_username="bob", is_sender=False, content=texto_recebido_alice)

    # Alice chama GET /chat/history/bob pela API
    res_history = client.get("/chat/history/bob")
    assert res_history.status_code == 200
    historico = res_history.json()["history"]

    assert len(historico) == 2
    assert historico[0]["is_sender"] == 1
    assert historico[0]["content"] == texto_alice
    assert historico[1]["is_sender"] == 0
    assert historico[1]["content"] == resposta_bob

    SecurityAuditor.log_step("TESTE", "=== TESTE DE COMUNICAÇÃO DA API CONCLUÍDO COM SUCESSO! ===")
