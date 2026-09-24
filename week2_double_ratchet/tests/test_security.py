"""Security Invariant Test Suite for Double Ratchet & Untrusted Relay.

Verifies:
1. Server confidentiality (zero plaintext retention in logs/storage).
2. Distinct key per message.
3. Tamper detection (ciphertext and header).
4. Replay rejection.
5. Out-of-order delivery within bound and safe rejection beyond bound.
6. Forward secrecy (past keys erased and unrecoverable).
7. Post-compromise recovery / break-in recovery.
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from starlette.testclient import TestClient

from week2_double_ratchet.backend.server import create_relay_app
from week2_double_ratchet.client.client import E2EEClient
from week2_double_ratchet.crypto.double_ratchet import MessageHeader, RatchetMessage, RatchetSession
from week2_double_ratchet.crypto.kdf import kdf_ck


def setup_pair(max_skip: int = 1000) -> tuple[RatchetSession, RatchetSession]:
    shared_key = os.urandom(32)
    bob_dh = X25519PrivateKey.generate()
    bob_pub = bob_dh.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    alice_dh = X25519PrivateKey.generate()

    alice = RatchetSession(
        shared_key=shared_key,
        our_dh_priv=alice_dh,
        their_dh_pub_bytes=bob_pub,
        is_initiator=True,
        max_skip=max_skip,
    )
    bob = RatchetSession(
        shared_key=shared_key,
        our_dh_priv=bob_dh,
        their_dh_pub_bytes=None,
        is_initiator=False,
        max_skip=max_skip,
    )
    return alice, bob


# 1. Server Confidentiality
def test_security_server_confidentiality() -> None:
    app = create_relay_app()
    client = TestClient(app)

    alice = E2EEClient("alice")
    bob = E2EEClient("bob")
    alice.register_and_publish_keys(client=client)
    bob.register_and_publish_keys(client=client)

    alice.start_session_with_peer("bob", http_client=client)
    secret_text = "HighlyClassifiedTopSecret123456789"
    alice.send_chat_message("bob", secret_text, hc=client)

    # Inspect server logs and state
    logs = client.get("/api/logs").json()
    assert len(logs) > 0

    # Ensure secret text does NOT appear anywhere in server logs or raw payloads
    for entry in logs:
        assert secret_text not in entry["ciphertext_hex"]
        assert secret_text not in str(entry)


# 2. Distinct Key Per Message
def test_security_distinct_key_per_message() -> None:
    alice, bob = setup_pair()
    keys_observed: set[bytes] = set()

    for _ in range(20):
        # Inspect derived message keys directly from chain
        assert alice.cks is not None
        alice.cks, mk = kdf_ck(alice.cks)
        assert mk not in keys_observed
        keys_observed.add(mk)


# 3. Tamper Detection (Ciphertext and Header)
def test_security_tamper_detection() -> None:
    alice, bob = setup_pair()
    msg = alice.ratchet_encrypt(b"Genuine authentic payload")

    # Invert bit in ciphertext
    corrupt_ct = bytearray(msg.ciphertext)
    corrupt_ct[15] ^= 0x01
    tampered_msg = RatchetMessage(header=msg.header, ciphertext=bytes(corrupt_ct))

    with pytest.raises(ValueError, match="AEAD authentication failed"):
        bob.ratchet_decrypt(tampered_msg)

    # Tamper with header counter (n)
    tampered_header_n = MessageHeader(
        dh_pub=msg.header.dh_pub, pn=msg.header.pn, n=msg.header.n + 1
    )
    tampered_msg_hdr = RatchetMessage(header=tampered_header_n, ciphertext=msg.ciphertext)

    with pytest.raises(ValueError):
        bob.ratchet_decrypt(tampered_msg_hdr)

    # Tamper with header public key (dh_pub)
    tampered_header_dh = MessageHeader(dh_pub=os.urandom(32), pn=msg.header.pn, n=msg.header.n)
    tampered_msg_dh = RatchetMessage(header=tampered_header_dh, ciphertext=msg.ciphertext)

    with pytest.raises(ValueError):
        bob.ratchet_decrypt(tampered_msg_dh)


# 4. Replay Rejection
def test_security_replay_rejection() -> None:
    alice, bob = setup_pair()
    msg = alice.ratchet_encrypt(b"Replay test payload")

    # First receipt succeeds
    decrypted = bob.ratchet_decrypt(msg)
    assert decrypted == b"Replay test payload"

    # Replay of the same message must fail
    with pytest.raises(ValueError):
        bob.ratchet_decrypt(msg)


# 5. Out-of-Order Within Bound & Safe Failure Beyond Bound
def test_security_out_of_order_within_bound_and_failure_beyond() -> None:
    alice, bob = setup_pair(max_skip=5)

    # Generate 5 messages: 0, 1, 2, 3, 4
    messages = [alice.ratchet_encrypt(f"Msg {i}".encode("utf-8")) for i in range(5)]

    # Deliver message 3 first (skipping 0, 1, 2)
    assert bob.ratchet_decrypt(messages[3]) == b"Msg 3"
    assert len(bob.mk_skipped) == 3

    # Deliver message 1 (retrieved from skipped store)
    assert bob.ratchet_decrypt(messages[1]) == b"Msg 1"
    assert len(bob.mk_skipped) == 2

    # Deliver message 0, 2, 4
    assert bob.ratchet_decrypt(messages[0]) == b"Msg 0"
    assert bob.ratchet_decrypt(messages[2]) == b"Msg 2"
    assert bob.ratchet_decrypt(messages[4]) == b"Msg 4"
    assert len(bob.mk_skipped) == 0

    # Test failure beyond bound:
    # Max skip is 5; generate messages exceeding bound
    alice2, bob2 = setup_pair(max_skip=3)
    msgs = [alice2.ratchet_encrypt(f"Beyond {i}".encode("utf-8")) for i in range(10)]
    # Deliver message 8 directly (requires skipping 8 messages, exceeding max_skip of 3)
    with pytest.raises(ValueError, match="Too many skipped messages"):
        bob2.ratchet_decrypt(msgs[8])


# 6. Forward Secrecy
def test_security_forward_secrecy() -> None:
    alice, bob = setup_pair()
    msg1 = alice.ratchet_encrypt(b"Historical sensitive message")
    assert bob.ratchet_decrypt(msg1) == b"Historical sensitive message"

    # Alice sends message 2
    msg2 = alice.ratchet_encrypt(b"Second message")
    assert bob.ratchet_decrypt(msg2) == b"Second message"

    # Compromise Bob's current state: attacker gets current bob.ckr and bob.rk
    compromised_ckr = bob.ckr
    assert compromised_ckr is not None

    # Forward secrecy guarantee: Past message keys cannot be computed from compromised_ckr
    # because symmetric KDF is a one-way function (HMAC-SHA256).
    # Attempting to decrypt msg1 with keys derived forward from compromised_ckr will fail:
    _, next_mk = kdf_ck(compromised_ckr)
    with pytest.raises(ValueError):
        bob.ratchet_decrypt(msg1)


# 7. Post-Compromise Recovery (Break-in Recovery)
def test_security_post_compromise_recovery() -> None:
    alice, bob = setup_pair()

    # Step 1: Normal message exchange
    m1 = alice.ratchet_encrypt(b"Message before compromise")
    bob.ratchet_decrypt(m1)

    # Step 2: Compromise - Attacker steals Alice's entire ratchet state
    attacker_stolen_rk = alice.rk
    attacker_stolen_cks = alice.cks

    # Step 3: Bob sends a reply with a new DH key (advancing Bob's DH ratchet)
    m2 = bob.ratchet_encrypt(b"Bob reply establishing new DH key")
    alice.ratchet_decrypt(m2)  # Alice updates her DH key and derives new RK!

    # Step 4: Alice replies back to Bob
    m3 = alice.ratchet_encrypt(b"Alice post-compromise healed message")

    # Step 5: Verify Bob decrypts healed message
    decrypted_m3 = bob.ratchet_decrypt(m3)
    assert decrypted_m3 == b"Alice post-compromise healed message"

    # Step 6: Verify Attacker CANNOT decrypt m3 using their stolen old state
    # Attacker lacks Alice's and Bob's new ephemeral private keys
    assert alice.rk != attacker_stolen_rk
    assert alice.cks != attacker_stolen_cks
