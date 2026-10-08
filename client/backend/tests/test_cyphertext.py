import pytest
from src.backend.session import SecureSession

def test_ciphertext_adulterado_e_rejeitado():

    # Alice e Bob estabelecem uma sessão legítima
    alice = SecureSession()
    bob = SecureSession()

    alice.establish_session(bob.get_public_key())
    bob.establish_session(alice.get_public_key())

    # Alice cria uma mensagem legítima
    pacote = alice.encrypt("Oier Bob, esta é uma mensagem secreta!")

    # Transformamos o pacote em bytearray para poder alterar um byte do conteúdo cifrado.
    pacote_adulterado = bytearray(pacote)

    # O pacote possui:
    #
    # [ IV ][ CIPHERTEXT ][ HMAC ]
    #
    # Vamos alterar um byte do ciphertext.
    # O HMAC original não será alterado.
    pacote_adulterado[20] ^= 1

    # Transformamos novamente em bytes
    pacote_adulterado = bytes(pacote_adulterado)

    # Bob deve detectar a adulteração através do HMAC
    # e rejeitar a mensagem.
    with pytest.raises(
        ValueError,
        match="Falha na validação do HMAC"
    ):
        bob.decrypt(pacote_adulterado)