# client/backend/tests/test_replay_protection.py
import json
import time

import pytest
from backend.session import MAX_FUTURE_SKEW_SECONDS, ReplayError, SecureSession
from backend.storage import LocalStorage


def _par_estabelecido():
    alice, bob = SecureSession(), SecureSession()
    alice.establish_session(bob.get_public_key())
    bob.establish_session(alice.get_public_key())
    return alice, bob


def test_mensagens_em_ordem_sao_aceitas_e_contador_avanca():
    alice, bob = _par_estabelecido()
    for i in range(1, 4):
        assert bob.decrypt(alice.encrypt(f"msg {i}")) == f"msg {i}"
    assert alice.send_seq == 3
    assert bob.recv_seq == 3


def test_replay_do_mesmo_pacote_e_rejeitado():
    alice, bob = _par_estabelecido()
    pacote = alice.encrypt("Transfere R$ 100")
    assert bob.decrypt(pacote) == "Transfere R$ 100"
    with pytest.raises(ReplayError):
        bob.decrypt(pacote)


def test_pacote_antigo_fora_de_ordem_e_rejeitado():
    alice, bob = _par_estabelecido()
    p1, p2 = alice.encrypt("um"), alice.encrypt("dois")
    assert bob.decrypt(p2) == "dois"
    with pytest.raises(ReplayError):
        bob.decrypt(p1)


def test_reflexao_para_o_proprio_remetente_e_rejeitada():
    alice, bob = _par_estabelecido()
    pacote = alice.encrypt("olá")
    with pytest.raises(ReplayError):
        alice.decrypt(pacote)


def test_timestamp_no_futuro_e_rejeitado():
    alice, bob = _par_estabelecido()
    envelope = {
        "seq": 1,
        "ts": int(time.time()) + MAX_FUTURE_SKEW_SECONDS + 3600,
        "sid": SecureSession._sender_id(alice.get_public_key()),
        "text": "do futuro",
    }
    pacote = alice.serpent.encrypt_message(json.dumps(envelope))
    with pytest.raises(ReplayError):
        bob.decrypt(pacote)


def test_payload_sem_cabecalho_antireplay_e_rejeitado():
    alice, bob = _par_estabelecido()
    pacote = alice.serpent.encrypt_message("texto puro sem seq")
    with pytest.raises(ReplayError):
        bob.decrypt(pacote)


def test_rejeicao_nao_avanca_contador():
    alice, bob = _par_estabelecido()
    pacote = alice.encrypt("a")
    bob.decrypt(pacote)
    with pytest.raises(ReplayError):
        bob.decrypt(pacote)
    assert bob.recv_seq == 1
    assert bob.decrypt(alice.encrypt("b")) == "b"


def test_contadores_sobrevivem_a_restauracao_da_sessao():
    alice, bob = _par_estabelecido()
    p1 = alice.encrypt("antes do restart")
    bob.decrypt(p1)

    bob_restaurado = SecureSession.from_persisted_state(
        session_key=bob.session_key,
        my_pub_pem=bob.get_public_key(),
        peer_pub_pem=bob.peer_public_key_pem,
        send_seq=bob.send_seq,
        recv_seq=bob.recv_seq,
    )
    # Replay após reiniciar o backend continua barrado
    with pytest.raises(ReplayError):
        bob_restaurado.decrypt(p1)
    assert bob_restaurado.decrypt(alice.encrypt("depois do restart")) == "depois do restart"


def test_contadores_persistidos_no_sqlite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    storage = LocalStorage("alice_replay_test")
    chave_local = b"\x01" * 32
    alice, bob = _par_estabelecido()

    storage.save_established_session(
        contact_username="bob",
        session_key=alice.session_key,
        my_ephemeral_pub_pem=alice.get_public_key(),
        peer_ephemeral_pub_pem=alice.peer_public_key_pem,
        local_storage_key=chave_local,
    )
    alice.encrypt("1")
    alice.encrypt("2")
    storage.update_session_counters("bob", alice.send_seq, alice.recv_seq)

    restauradas = LocalStorage("alice_replay_test").load_all_established_sessions(chave_local)
    assert restauradas["bob"].send_seq == 2
    assert restauradas["bob"].recv_seq == 0
