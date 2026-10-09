# client/backend/tests/test_session.py
import pytest
from backend.session import SecureSession


def test_fluxo_completo_com_safety_number():
    """Valida o ciclo de vida da sessão: handshake, safety number e cifragem bidirecional."""
    # 1. Instanciação dos participantes
    alice = SecureSession()
    bob = SecureSession()

    assert not alice.is_established
    assert not bob.is_established

    # 2. Handshake (troca de chaves públicas)
    pk_alice = alice.get_public_key()
    pk_bob = bob.get_public_key()

    alice.establish_session(pk_bob)
    bob.establish_session(pk_alice)

    assert alice.is_established
    assert bob.is_established

    # 3. Verificação do Safety Number
    safety_alice = alice.get_safety_number()
    safety_bob = bob.get_safety_number()

    print(f"\n[DEMO] Safety Number Alice: {safety_alice}")
    print(f"[DEMO] Safety Number Bob:   {safety_bob}")

    assert safety_alice == safety_bob
    assert len(safety_alice.split()) == 6

    # 4. Envio de mensagem Alice -> Bob
    msg_alice = "Olá Bob! Conexão segura e autenticada."
    payload_alice = alice.encrypt(msg_alice)
    assert bob.decrypt(payload_alice) == msg_alice

    # 5. Resposta Bob -> Alice
    msg_bob = "Confirmado Alice! Canal Serpent + HMAC ativo."
    payload_bob = bob.encrypt(msg_bob)
    assert alice.decrypt(payload_bob) == msg_bob


def test_ataque_mitm_completo_com_deteccao_safety_number():
    """Simula um ataque Man-in-the-Middle (MitM) completo.

    Demonstra:
    1. Interceptação da troca de chaves públicas na rede.
    2. Quebra de confidencialidade (atacante lê a mensagem original).
    3. Quebra de integridade sem erro de HMAC (atacante adultera e recifra).
    4. Detecção conclusiva do ataque através da divergência do Safety Number.
    """
    # 1. Instâncias legítimas e o atacante na rede
    alice = SecureSession()
    bob = SecureSession()

    # O atacante precisa de 2 instâncias para intermediar os dois canais
    atacante_lado_alice = SecureSession()
    atacante_lado_bob = SecureSession()

    # 2. Interceptação do Handshake (Troca de Chaves Públicas)
    pk_alice = alice.get_public_key()
    pk_bob = bob.get_public_key()

    # Alice acha que recebeu a chave de Bob, mas recebeu a do atacante
    alice.establish_session(atacante_lado_alice.get_public_key())
    atacante_lado_alice.establish_session(pk_alice)

    # Bob acha que recebeu a chave de Alice, mas recebeu a do atacante
    bob.establish_session(atacante_lado_bob.get_public_key())
    atacante_lado_bob.establish_session(pk_bob)

    # 3. Alice envia mensagem confidencial
    msg_original = "Alice: Transfere R$ 100 para o Bob"
    payload_alice = alice.encrypt(msg_original)

    # 4. Atacante intercepta e decifra o pacote de Alice
    msg_interceptada = atacante_lado_alice.decrypt(payload_alice)
    assert msg_interceptada == msg_original  # Atacante conseguiu ler o segredo!

    # 5. Atacante adultera o conteúdo e recifra para Bob
    msg_adulterada = "Alice: Transfere R$ 10.000 para a conta do Hacker"
    payload_adulterado = atacante_lado_bob.encrypt(msg_adulterada)

    # 6. Bob recebe e decifra sem nenhum erro de HMAC
    msg_recebida_bob = bob.decrypt(payload_adulterado)
    assert msg_recebida_bob == msg_adulterada  # Bob foi enganado pela mensagem falsa

    # 7. A Defesa: Verificação do Safety Number fora de banda (ex: por telefone/QR Code)
    safety_alice = alice.get_safety_number()
    safety_bob = bob.get_safety_number()

    print(f"\n[ALERTA MITM]")
    print(f"Safety Number exibido para Alice: {safety_alice}")
    print(f"Safety Number exibido para Bob:   {safety_bob}")

    # A prova matemática do ataque: os números são obrigados a divergir!
    assert safety_alice != safety_bob