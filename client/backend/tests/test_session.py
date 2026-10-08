import pytest
from src.backend.session import SecureSession

def test_mensagem_com_chave_errada_e_rejeitada():

    # Alice e Bob estabelecem uma sessão legítima
    alice = SecureSession()
    bob = SecureSession()

    alice.establish_session(bob.get_public_key())
    bob.establish_session(alice.get_public_key())

    # Um terceiro participante cria outra sessão 
    # Essa sessão possui uma chave privada diferente
    atacante = SecureSession()

    # O atacante tenta estabelecer uma sessão usando a chave pública do Bob
    atacante.establish_session(bob.get_public_key())

    # O atacante cifra uma mensagem.
    pacote = atacante.encrypt("Mensagem falsa!")

    # Bob tenta receber a mensagem.
    # Como o pacote foi cifrado com outra chave,o HMAC não bate e o sistema deve rejeitar a mensagem
    with pytest.raises(ValueError, match="Falha na validação do HMAC"):
        bob.decrypt(pacote)