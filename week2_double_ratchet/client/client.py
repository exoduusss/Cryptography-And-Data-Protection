"""End-to-End Encrypted Client implementation.

Educational reference implementation. Manages local cryptographic sessions,
communicates with the untrusted relay, and serves a local web UI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from week2_double_ratchet.crypto.double_ratchet import RatchetMessage, RatchetSession
from week2_double_ratchet.crypto.identity import IdentityKeyPair, PreKeyBundle
from week2_double_ratchet.crypto.kdf import compute_safety_number
from week2_double_ratchet.crypto.serialization import (
    decrypt_session_at_rest,
    encrypt_session_at_rest,
)
from week2_double_ratchet.crypto.x3dh import x3dh_initiator, x3dh_receiver


class E2EEClient:
    """Client entity managing cryptographic state, X3DH agreements, and Double Ratchet sessions."""

    def __init__(self, user_id: str, relay_base_url: str = "http://localhost:8000") -> None:
        self.user_id = user_id
        self.relay_url = relay_base_url.rstrip("/")
        self.identity = IdentityKeyPair(user_id=user_id)

        # Prekey stores
        self.signed_prekey_priv, self.signed_prekey_pub, self.signed_prekey_sig = (
            self.identity.create_signed_prekey()
        )
        self.one_time_privs: dict[bytes, X25519PrivateKey] = {}
        self.one_time_pub_list: list[bytes] = []

        opk_pairs = self.identity.create_one_time_prekeys(count=5)
        for priv, pub in opk_pairs:
            self.one_time_privs[pub] = priv
            self.one_time_pub_list.append(pub)

        # Active ratchet sessions: peer_id -> RatchetSession
        self.sessions: dict[str, RatchetSession] = {}
        # Peer identity keys: peer_id -> identity_dh_pub
        self.peer_identities: dict[str, bytes] = {}
        # X3DH master secrets: peer_id -> master_secret
        self.shared_master_secrets: dict[str, bytes] = {}
        # Message history & shared notes storage
        self.chat_history: list[dict[str, Any]] = []
        self.shared_notes: dict[str, str] = {}

    def register_and_publish_keys(self, client: httpx.Client | None = None) -> None:
        """Register identity and publish signed prekey bundle to the untrusted relay."""
        http_client = client if client is not None else httpx.Client(base_url=self.relay_url)
        # Register user
        reg_payload = {
            "user_id": self.user_id,
            "identity_dh_pub": self.identity.dh_pub_bytes.hex(),
            "identity_sign_pub": self.identity.sign_pub_bytes.hex(),
        }
        res = http_client.post("/api/register", json=reg_payload)
        res.raise_for_status()

        # Upload prekeys
        prekey_payload = {
            "user_id": self.user_id,
            "signed_prekey_pub": self.signed_prekey_pub.hex(),
            "signed_prekey_sig": self.signed_prekey_sig.hex(),
            "one_time_prekeys": [pub.hex() for pub in self.one_time_pub_list],
        }
        res2 = http_client.post("/api/prekeys", json=prekey_payload)
        res2.raise_for_status()

    def start_session_with_peer(
        self,
        peer_id: str,
        http_client: httpx.Client | None = None,
    ) -> tuple[RatchetSession, dict[str, Any]]:
        """Fetch peer prekey bundle, execute X3DH initiator, and initialize Double Ratchet session.

        Returns:
            Tuple of (RatchetSession, x3dh_initial_packet_dict).
        """
        hc = http_client if http_client is not None else httpx.Client(base_url=self.relay_url)
        resp = hc.get(f"/api/prekeys/{peer_id}")
        resp.raise_for_status()
        bundle_data = resp.json()

        peer_bundle = PreKeyBundle(
            user_id=peer_id,
            identity_dh_pub=bytes.fromhex(bundle_data["identity_dh_pub"]),
            identity_sign_pub=bytes.fromhex(bundle_data["identity_sign_pub"]),
            signed_prekey_pub=bytes.fromhex(bundle_data["signed_prekey_pub"]),
            signed_prekey_sig=bytes.fromhex(bundle_data["signed_prekey_sig"]),
            one_time_prekey_pub=bytes.fromhex(bundle_data["one_time_prekey_pub"])
            if bundle_data["one_time_prekey_pub"]
            else None,
        )

        shared_master_secret, ephemeral_pub, used_opk = x3dh_initiator(
            alice_identity=self.identity,
            bob_bundle=peer_bundle,
        )

        # Alice's initial ratchet keypair
        alice_ratchet_priv = X25519PrivateKey.generate()

        session = RatchetSession(
            shared_key=shared_master_secret,
            our_dh_priv=alice_ratchet_priv,
            their_dh_pub_bytes=peer_bundle.signed_prekey_pub,
            is_initiator=True,
        )
        self.sessions[peer_id] = session
        self.peer_identities[peer_id] = peer_bundle.identity_dh_pub
        self.shared_master_secrets[peer_id] = shared_master_secret

        initial_packet = {
            "alice_identity_dh_pub": self.identity.dh_pub_bytes.hex(),
            "alice_ephemeral_pub": ephemeral_pub.hex(),
            "used_one_time_prekey_pub": used_opk.hex() if used_opk else None,
        }
        return session, initial_packet

    def receive_initial_session(
        self,
        peer_id: str,
        initial_packet: dict[str, Any],
    ) -> RatchetSession:
        """Process incoming X3DH handshake as receiver
        and initialize local Double Ratchet session.
        """
        alice_id_pub = bytes.fromhex(initial_packet["alice_identity_dh_pub"])
        alice_ek_pub = bytes.fromhex(initial_packet["alice_ephemeral_pub"])
        used_opk = (
            bytes.fromhex(initial_packet["used_one_time_prekey_pub"])
            if initial_packet.get("used_one_time_prekey_pub")
            else None
        )

        shared_master_secret = x3dh_receiver(
            bob_identity=self.identity,
            bob_signed_prekey_priv=self.signed_prekey_priv,
            bob_one_time_privs=self.one_time_privs,
            alice_identity_dh_pub=alice_id_pub,
            alice_ephemeral_pub=alice_ek_pub,
            used_one_time_pub=used_opk,
        )

        session = RatchetSession(
            shared_key=shared_master_secret,
            our_dh_priv=self.signed_prekey_priv,
            their_dh_pub_bytes=None,
            is_initiator=False,
        )
        self.sessions[peer_id] = session
        self.peer_identities[peer_id] = alice_id_pub
        self.shared_master_secrets[peer_id] = shared_master_secret
        return session

    def send_chat_message(
        self,
        peer_id: str,
        plaintext: str,
        hc: httpx.Client | None = None,
    ) -> RatchetMessage:
        """Encrypt and dispatch a chat message to a peer."""
        session = self.sessions.get(peer_id)
        if session is None:
            raise ValueError(f"No active session with {peer_id}. Run X3DH handshake first.")

        # Bind peer IDs into Associated Data prefix
        ad_prefix = self.user_id.encode("utf-8") + b":" + peer_id.encode("utf-8") + b":"
        msg_packet = session.ratchet_encrypt(plaintext.encode("utf-8"), ad_prefix=ad_prefix)

        payload_dict = {
            "sender_id": self.user_id,
            "recipient_id": peer_id,
            "message_type": "chat",
            "payload": msg_packet.to_dict(),
        }

        client = hc if hc is not None else httpx.Client(base_url=self.relay_url)
        resp = client.post("/api/send", json=payload_dict)
        resp.raise_for_status()

        self.chat_history.append({"sender": self.user_id, "text": plaintext})
        return msg_packet

    def receive_message(self, packet: dict[str, Any]) -> str:
        """Decrypt an incoming message packet from peer."""
        sender_id = packet["sender_id"]
        msg_type = packet.get("message_type", "chat")
        session = self.sessions.get(sender_id)
        if session is None:
            raise ValueError(f"No active session found for sender '{sender_id}'")

        ad_prefix = sender_id.encode("utf-8") + b":" + self.user_id.encode("utf-8") + b":"
        ratchet_msg = RatchetMessage.from_dict(packet["payload"])
        decrypted_bytes = session.ratchet_decrypt(ratchet_msg, ad_prefix=ad_prefix)
        text = decrypted_bytes.decode("utf-8")

        if msg_type == "chat":
            self.chat_history.append({"sender": sender_id, "text": text})
        elif msg_type == "note":
            note_data = json.loads(text)
            self.shared_notes[note_data.get("title", "default")] = note_data.get("body", "")

        return text

    def update_shared_note(
        self,
        peer_id: str,
        title: str,
        body: str,
        hc: httpx.Client | None = None,
    ) -> RatchetMessage:
        """Transmit an encrypted collaborative note update."""
        session = self.sessions.get(peer_id)
        if session is None:
            raise ValueError(f"No active session with {peer_id}")

        note_payload = json.dumps({"title": title, "body": body}).encode("utf-8")
        ad_prefix = self.user_id.encode("utf-8") + b":" + peer_id.encode("utf-8") + b":"
        msg_packet = session.ratchet_encrypt(note_payload, ad_prefix=ad_prefix)

        payload_dict = {
            "sender_id": self.user_id,
            "recipient_id": peer_id,
            "message_type": "note",
            "payload": msg_packet.to_dict(),
        }

        client = hc if hc is not None else httpx.Client(base_url=self.relay_url)
        resp = client.post("/api/send", json=payload_dict)
        resp.raise_for_status()

        self.shared_notes[title] = body
        return msg_packet

    def get_safety_number(self, peer_id: str) -> str:
        """Compute the 12-digit mutual safety number with peer."""
        peer_pub = self.peer_identities.get(peer_id)
        if peer_pub is None:
            raise ValueError(f"Peer identity key unknown for {peer_id}")
        return compute_safety_number(self.identity.dh_pub_bytes, peer_pub)

    def save_state_to_file(self, filepath: Path | str, passphrase: str) -> None:
        """Encrypt and persist all active sessions to disk."""
        serialized_sessions = {
            peer_id: encrypt_session_at_rest(session, passphrase).hex()
            for peer_id, session in self.sessions.items()
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(serialized_sessions, f)

    def load_state_from_file(self, filepath: Path | str, passphrase: str) -> None:
        """Load and decrypt sessions from disk."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        for peer_id, hex_blob in data.items():
            blob = bytes.fromhex(hex_blob)
            self.sessions[peer_id] = decrypt_session_at_rest(blob, passphrase)


def create_local_client_app(client: E2EEClient) -> FastAPI:
    """Create local FastAPI web server to expose client state to browser UI."""
    app = FastAPI(title=f"E2EE Local Client ({client.user_id})")

    ui_dir = Path(__file__).parent / "ui"
    if ui_dir.exists():
        app.mount("/static", StaticFiles(directory=str(ui_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> Any:
        index_file = ui_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return HTMLResponse("<h1>Client UI Not Found</h1>")

    @app.get("/api/local/status")
    def get_status() -> dict[str, Any]:
        session_info = {}
        for peer, s in client.sessions.items():
            session_info[peer] = {
                "ns": s.ns,
                "nr": s.nr,
                "pn": s.pn,
                "skipped_count": len(s.mk_skipped),
                "our_dh_pub": s.our_dh_pub_bytes.hex()[:16] + "...",
                "their_dh_pub": s.dhr.hex()[:16] + "..." if s.dhr else None,
                "root_key_fingerprint": s.rk.hex()[:16] + "...",
                "safety_number": client.get_safety_number(peer)
                if peer in client.peer_identities
                else "N/A",
            }
        return {
            "user_id": client.user_id,
            "identity_dh_pub": client.identity.dh_pub_bytes.hex()[:16] + "...",
            "active_sessions": session_info,
            "chat_history": client.chat_history,
            "shared_notes": client.shared_notes,
        }

    return app
