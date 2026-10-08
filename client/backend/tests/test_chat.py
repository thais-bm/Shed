from backend.session import SecureSession


def test_alice_e_bob_conseguem_se_comunicar():

    # Alice e Bob criam suas sessões seguras
    alice = SecureSession()
    bob = SecureSession()

    #Handshake ECDH: Alice envia sua chave pública para Bob, e Bob envia a dele para Alice.
    alice.establish_session(
        bob.get_public_key()
    )
    
    bob.establish_session(
        alice.get_public_key()
    )

    # Alice -> Bob
    mensagem = "Oierrr Bob!"

    pacote = alice.encrypt(mensagem)

    mensagem_recebida = bob.decrypt(pacote)

    assert mensagem_recebida == mensagem

    # Bob -> Alice

    resposta = "Helllor Alice :D!"

    pacote = bob.encrypt(resposta)

    resposta_recebida = alice.decrypt(pacote)

    assert resposta_recebida == resposta