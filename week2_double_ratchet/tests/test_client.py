"""Unit tests for the E2EEClient entity and local API."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from week2_double_ratchet.backend.server import create_relay_app
from week2_double_ratchet.client.client import E2EEClient, create_local_client_app


@pytest.fixture
def relay_client() -> TestClient:
    app = create_relay_app()
    return TestClient(app)


def test_client_full_conversation_and_notes(relay_client: TestClient) -> None:
    alice = E2EEClient("alice")
    bob = E2EEClient("bob")

    alice.register_and_publish_keys(client=relay_client)
    bob.register_and_publish_keys(client=relay_client)

    # Handshake
    _, hs_packet = alice.start_session_with_peer("bob", http_client=relay_client)
    bob.receive_initial_session("alice", hs_packet)

    # Chat messages
    msg1 = alice.send_chat_message("bob", "Hello Bob!", hc=relay_client)
    delivered1 = {
        "sender_id": "alice",
        "recipient_id": "bob",
        "message_type": "chat",
        "payload": msg1.to_dict(),
    }
    pt1 = bob.receive_message(delivered1)
    assert pt1 == "Hello Bob!"

    # Shared notes
    note_msg = alice.update_shared_note(
        "bob", title="Plan", body="Step 1: Test coverage", hc=relay_client
    )
    delivered_note = {
        "sender_id": "alice",
        "recipient_id": "bob",
        "message_type": "note",
        "payload": note_msg.to_dict(),
    }
    bob.receive_message(delivered_note)
    assert bob.shared_notes["Plan"] == "Step 1: Test coverage"

    # Safety number
    sn_a = alice.get_safety_number("bob")
    sn_b = bob.get_safety_number("alice")
    assert sn_a == sn_b

    # Persistence to file
    with tempfile.TemporaryDirectory() as tmpdir:
        save_file = Path(tmpdir) / "alice_sessions.json"
        alice.save_state_to_file(save_file, "secretPass123")

        # Create new client and restore
        alice_restored = E2EEClient("alice")
        alice_restored.peer_identities["bob"] = alice.peer_identities["bob"]
        alice_restored.load_state_from_file(save_file, "secretPass123")
        assert "bob" in alice_restored.sessions
        assert alice_restored.sessions["bob"].ns == alice.sessions["bob"].ns


def test_local_client_app(relay_client: TestClient) -> None:
    alice = E2EEClient("alice")
    app = create_local_client_app(alice)
    tc = TestClient(app)

    # Status endpoint
    status_resp = tc.get("/api/local/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["user_id"] == "alice"

    # Index page
    index_resp = tc.get("/")
    assert index_resp.status_code == 200
