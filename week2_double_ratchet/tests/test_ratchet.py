"""Unit tests for the Double Ratchet state machine and key advancement."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from week2_double_ratchet.crypto.double_ratchet import MessageHeader, RatchetSession


def setup_pair() -> tuple[RatchetSession, RatchetSession]:
    shared_key = os.urandom(32)
    bob_initial_dh = X25519PrivateKey.generate()
    bob_dh_pub_bytes = bob_initial_dh.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    alice_initial_dh = X25519PrivateKey.generate()

    alice = RatchetSession(
        shared_key=shared_key,
        our_dh_priv=alice_initial_dh,
        their_dh_pub_bytes=bob_dh_pub_bytes,
        is_initiator=True,
    )
    bob = RatchetSession(
        shared_key=shared_key,
        our_dh_priv=bob_initial_dh,
        their_dh_pub_bytes=None,
        is_initiator=False,
    )
    return alice, bob


def test_ratchet_linear_exchange() -> None:
    alice, bob = setup_pair()

    for i in range(5):
        msg_text = f"Message number {i}".encode("utf-8")
        packet = alice.ratchet_encrypt(msg_text)
        decrypted = bob.ratchet_decrypt(packet)
        assert decrypted == msg_text
        assert bob.nr == i + 1


def test_ratchet_bidirectional_turns() -> None:
    alice, bob = setup_pair()

    # 1. Alice -> Bob
    msg1 = alice.ratchet_encrypt(b"Hello Bob")
    assert bob.ratchet_decrypt(msg1) == b"Hello Bob"

    # 2. Bob -> Alice (triggers DH ratchet step)
    msg2 = bob.ratchet_encrypt(b"Hello Alice")
    assert alice.ratchet_decrypt(msg2) == b"Hello Alice"

    # 3. Alice -> Bob again
    msg3 = alice.ratchet_encrypt(b"Good to hear from you")
    assert bob.ratchet_decrypt(msg3) == b"Good to hear from you"

    # 4. Bob -> Alice
    msg4 = bob.ratchet_encrypt(b"Double Ratchet is operating correctly")
    assert alice.ratchet_decrypt(msg4) == b"Double Ratchet is operating correctly"


def test_header_serialization() -> None:
    pub = os.urandom(32)
    h = MessageHeader(dh_pub=pub, pn=7, n=12)
    binary = h.to_bytes()
    assert len(binary) == 40
    restored = MessageHeader.from_bytes(binary)
    assert restored == h
