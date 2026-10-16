import json
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from server import app, get_db
from server.database import RelayDatabase


@pytest.fixture()
def client(tmp_path):
    test_db_path = tmp_path / "test_relay.db"
    test_db = RelayDatabase(db_path=test_db_path)

    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_register_and_login_flow(client: TestClient):
    # 1. Registro de Alice
    reg_res = client.post(
        "/auth/register",
        json={
            "username": "Alice",
            "password": "super-secret-password",
            "public_identity_key": "PEM_KEY_ALICE",
        },
    )
    assert reg_res.status_code == 201
    data = reg_res.json()
    assert data["username"] == "alice"
    assert "access_token" in data

    # 2. Tentativa de registro duplicado deve retornar 409
    dup_res = client.post(
        "/auth/register",
        json={"username": "alice", "password": "other-password"},
    )
    assert dup_res.status_code == 409

    # 3. Login com senha errada deve retornar 401
    bad_login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    assert bad_login.status_code == 401

    # 4. Login válido retorna novo JWT
    ok_login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "super-secret-password"},
    )
    assert ok_login.status_code == 200
    assert "access_token" in ok_login.json()


def test_search_and_friendship_crud(client: TestClient):
    # Registra Alice e Bob
    alice_token = client.post(
        "/auth/register",
        json={"username": "alice", "password": "password123"},
    ).json()["access_token"]

    bob_token = client.post(
        "/auth/register",
        json={"username": "bob", "password": "password123"},
    ).json()["access_token"]

    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}

    # 1. Alice busca por "bo"
    search_res = client.get("/users/search?q=bo", headers=alice_headers)
    assert search_res.status_code == 200
    results = search_res.json()
    assert len(results) == 1
    assert results[0]["username"] == "bob"

    # 2. Alice envia solicitação de amizade para Bob
    req_res = client.post("/friends/request/bob", headers=alice_headers)
    assert req_res.status_code == 200
    assert req_res.json()["status"] == "PENDING"

    # 3. Bob verifica suas solicitações pendentes
    bob_friends = client.get("/friends", headers=bob_headers).json()
    assert bob_friends["pending_received"] == ["alice"]
    assert bob_friends["friends"] == []

    # 4. Bob aceita a solicitação de Alice
    acc_res = client.post("/friends/accept/alice", headers=bob_headers)
    assert acc_res.status_code == 200
    assert acc_res.json()["status"] == "ACCEPTED"

    # 5. Ambos agora aparecem como amigos confirmados
    assert client.get("/friends", headers=alice_headers).json()["friends"] == ["bob"]
    assert client.get("/friends", headers=bob_headers).json()["friends"] == ["alice"]

    # 6. Alice remove Bob da lista de amigos
    del_res = client.delete("/friends/bob", headers=alice_headers)
    assert del_res.status_code == 200
    assert client.get("/friends", headers=alice_headers).json()["friends"] == []


def test_websocket_auth_and_offline_queue(client: TestClient, monkeypatch, tmp_path):
    # Garante que o endpoint WebSocket use o mesmo banco temporário do teste
    monkeypatch.setenv("SHED_RELAY_DB", str(tmp_path / "test_relay.db"))

    alice_token = client.post(
        "/auth/register",
        json={"username": "alice", "password": "password123"},
    ).json()["access_token"]

    bob_token = client.post(
        "/auth/register",
        json={"username": "bob", "password": "password123"},
    ).json()["access_token"]

    # 1. Tentativa de conexão sem token para usuário registrado deve fechar com 1008
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/alice") as ws:
            ws.receive_text()
    assert exc_info.value.code == 1008

    # 2. Tentativa de enviar mensagem ANTES de serem amigos deve ser bloqueada (Friends-Only Routing)
    envelope = {
        "type": "CHAT_MESSAGE",
        "from": "alice",
        "to": "bob",
        "payload": "deadbeef",
    }
    with client.websocket_connect(f"/ws/alice?token={alice_token}") as ws_alice:
        ws_alice.send_text(json.dumps(envelope))
        err_msg = json.loads(ws_alice.receive_text())
        assert err_msg["type"] == "ERROR"
        assert "amigos aceitos" in err_msg["reason"]

    # 3. Alice e Bob tornam-se amigos
    client.post("/friends/request/bob", headers={"Authorization": f"Bearer {alice_token}"})
    client.post("/friends/accept/alice", headers={"Authorization": f"Bearer {bob_token}"})

    # 4. Alice conecta autenticada e envia mensagem enquanto Bob está offline
    with client.websocket_connect(f"/ws/alice?token={alice_token}") as ws_alice:
        ws_alice.send_text(json.dumps(envelope))

    # 5. Bob conecta mais tarde com seu JWT e recebe a mensagem offline imediatamente
    with client.websocket_connect(f"/ws/bob?token={bob_token}") as ws_bob:
        received = json.loads(ws_bob.receive_text())
        assert received == envelope
