import pytest
from backend.crypto import IdentityKeyManager, PasswordKeyDeriver
from backend.session import SecureSession
from backend.storage import LocalStorage


def test_split_key_derivation_and_encrypted_identity_vault(tmp_path):
    """
    Valida a Ideia 3 (Split-Key Password Derivation):
    - A senha mestre gera duas chaves independentes (local_storage_key e relay_login_secret).
    - A chave privada de identidade ECDSA fica cifrada no SQLite local com local_storage_key.
    - Uma senha incorreta não consegue abrir a chave privada local.
    """
    local_key, relay_secret = PasswordKeyDeriver.derive_master_keys("alice", "MinhaSenhaSecreta!")

    assert len(local_key) == 32
    assert len(relay_secret) == 64
    assert "MinhaSenhaSecreta!" not in relay_secret

    # Outro usuário com a mesma senha gera chaves diferentes (graças ao salt do username)
    bob_local_key, bob_relay_secret = PasswordKeyDeriver.derive_master_keys("bob", "MinhaSenhaSecreta!")
    assert local_key != bob_local_key
    assert relay_secret != bob_relay_secret

    # Gera e cifra a Chave Privada de Identidade no banco local
    id_mgr = IdentityKeyManager()
    priv, pub = id_mgr.generate_identity_key_pair()
    pub_pem = id_mgr.export_public_key(pub).decode("utf-8")
    encrypted_priv_pem = id_mgr.export_private_key(priv, local_storage_key=local_key)

    db = LocalStorage("alice", db_dir=tmp_path)
    db.save_my_identity(encrypted_priv_pem, pub_pem)

    saved = db.get_my_identity()
    assert saved is not None

    # Senha correta desbloqueia a chave privada
    loaded_priv = id_mgr.load_private_key(saved["encrypted_private_key_pem"], local_storage_key=local_key)
    assert id_mgr.export_public_key(loaded_priv.public_key()).decode("utf-8") == pub_pem

    # Senha errada falha ao descriptografar a chave privada
    wrong_local_key, _ = PasswordKeyDeriver.derive_master_keys("alice", "SenhaErrada")
    with pytest.raises(ValueError):
        id_mgr.load_private_key(saved["encrypted_private_key_pem"], local_storage_key=wrong_local_key)


def test_signed_ecdh_handshake_prevents_mitm_key_swap():
    """
    Valida a Ideia 2 (Chaves de Identidade + Assinatura ECDSA no Handshake ECDH):
    - Alice e Bob assinam suas chaves efêmeras ECDH com suas Chaves de Identidade.
    - Se um atacante (ou Relé malicioso) tentar trocar a chave efêmera ECDH no meio do caminho,
      a verificação ECDSA bloqueia o handshake imediatamente!
    """
    id_mgr = IdentityKeyManager()
    alice_id_priv, alice_id_pub = id_mgr.generate_identity_key_pair()
    bob_id_priv, bob_id_pub = id_mgr.generate_identity_key_pair()

    alice_id_pub_pem = id_mgr.export_public_key(alice_id_pub)
    bob_id_pub_pem = id_mgr.export_public_key(bob_id_pub)

    # 1. Caminho Feliz: Handshake assinado legítimo
    alice_session = SecureSession()
    bob_session = SecureSession()

    alice_eph_pub, alice_sig = alice_session.get_signed_public_key(alice_id_priv)
    bob_eph_pub, bob_sig = bob_session.get_signed_public_key(bob_id_priv)

    bob_session.establish_session(
        peer_public_key_pem=alice_eph_pub,
        signature=alice_sig,
        peer_identity_public_key_pem=alice_id_pub_pem,
    )
    alice_session.establish_session(
        peer_public_key_pem=bob_eph_pub,
        signature=bob_sig,
        peer_identity_public_key_pem=bob_id_pub_pem,
    )

    ciphertext = alice_session.encrypt("Mensagem autenticada com ECDSA + Serpent!")
    assert bob_session.decrypt(ciphertext) == "Mensagem autenticada com ECDSA + Serpent!"

    # 2. Ataque MitM: Hacker substitui a chave pública efêmera de Alice pela dele
    hacker_session = SecureSession()
    hacker_eph_pub = hacker_session.get_public_key()

    bob_victim_session = SecureSession()
    with pytest.raises(ValueError, match="Assinatura ECDSA inválida"):
        bob_victim_session.establish_session(
            peer_public_key_pem=hacker_eph_pub,
            signature=alice_sig,  # Assinatura de Alice não bate com a chave efêmera do hacker!
            peer_identity_public_key_pem=alice_id_pub_pem,
        )


def test_tofu_pinning_detects_rogue_relay_identity_swap(tmp_path):
    """
    Valida o TOFU (Trust On First Use) no armazenamento local:
    - No primeiro contato com Alice, Bob fixa a Chave de Identidade pública dela.
    - Se o Servidor Relé tentar entregar uma Chave de Identidade falsa para Alice no futuro,
      o banco local de Bob detecta a mudança e bloqueia a conexão!
    """
    id_mgr = IdentityKeyManager()
    _, alice_real_pub = id_mgr.generate_identity_key_pair()
    _, hacker_fake_pub = id_mgr.generate_identity_key_pair()

    alice_real_pem = id_mgr.export_public_key(alice_real_pub).decode("utf-8")
    hacker_fake_pem = id_mgr.export_public_key(hacker_fake_pub).decode("utf-8")

    bob_db = LocalStorage("bob", db_dir=tmp_path)

    # 1º contato: fixa a chave de Alice (TOFU)
    assert bob_db.verify_or_pin_contact_identity("alice", alice_real_pem) is True

    # 2º contato com a mesma chave: validado com sucesso
    assert bob_db.verify_or_pin_contact_identity("alice", alice_real_pem) is True

    # 3º contato: Relé malicioso tenta enviar a chave de identidade do hacker no lugar da de Alice
    with pytest.raises(ValueError, match="ALERTA MITM \\(TOFU\\)"):
        bob_db.verify_or_pin_contact_identity("alice", hacker_fake_pem)
