"""Unit tests for FastAPI untrusted relay server and WebSocket switchboard."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from week2_double_ratchet.backend.server import create_relay_app


@pytest.fixture
def client() -> TestClient:
    app = create_relay_app()
    return TestClient(app)


def test_backend_registration_and_prekeys(client: TestClient) -> None:
    # 1. Register user
    reg_payload = {
        "user_id": "carol",
        "identity_dh_pub": "aa" * 32,
        "identity_sign_pub": "bb" * 32,
    }
    r = client.post("/api/register", json=reg_payload)
    assert r.status_code == 200
    assert r.json()["status"] == "registered"

    # List users
    users = client.get("/api/users").json()
    assert "carol" in users

    # 2. Upload prekeys
    prekey_payload = {
        "user_id": "carol",
        "signed_prekey_pub": "cc" * 32,
        "signed_prekey_sig": "dd" * 64,
        "one_time_prekeys": ["11" * 32, "22" * 32],
    }
    r_pk = client.post("/api/prekeys", json=prekey_payload)
    assert r_pk.status_code == 200
    assert r_pk.json()["one_time_prekeys_count"] == 2

    # 3. Fetch prekey bundle (pops first one-time prekey)
    b1 = client.get("/api/prekeys/carol").json()
    assert b1["one_time_prekey_pub"] == "11" * 32

    # Second fetch gets next one-time prekey
    b2 = client.get("/api/prekeys/carol").json()
    assert b2["one_time_prekey_pub"] == "22" * 32

    # Third fetch has none
    b3 = client.get("/api/prekeys/carol").json()
    assert b3["one_time_prekey_pub"] is None


def test_backend_error_cases(client: TestClient) -> None:
    # Upload prekeys for unregistered user
    r = client.post(
        "/api/prekeys",
        json={
            "user_id": "ghost",
            "signed_prekey_pub": "00" * 32,
            "signed_prekey_sig": "00" * 64,
            "one_time_prekeys": [],
        },
    )
    assert r.status_code == 404

    # Fetch bundle for unknown user
    r_unknown = client.get("/api/prekeys/unknown_user")
    assert r_unknown.status_code == 404


def test_backend_websocket_messaging(client: TestClient) -> None:
    # Connect two clients via websocket
    with client.websocket_connect("/ws/alice") as ws_alice:
        with client.websocket_connect("/ws/bob") as ws_bob:
            # Alice sends message to Bob
            packet = {
                "sender_id": "alice",
                "recipient_id": "bob",
                "message_type": "chat",
                "payload": {
                    "header": {"dh_pub": "00" * 32, "pn": 0, "n": 0},
                    "ciphertext": "deadbeef",
                },
            }
            ws_alice.send_json(packet)
            received = ws_bob.receive_json()
            assert received["sender_id"] == "alice"
            assert received["payload"]["ciphertext"] == "deadbeef"
