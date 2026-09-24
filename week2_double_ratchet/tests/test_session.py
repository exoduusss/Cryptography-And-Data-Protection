"""Unit tests for session state serialization and encrypted persistence at rest."""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from week2_double_ratchet.crypto.double_ratchet import RatchetSession
from week2_double_ratchet.crypto.serialization import (
    decrypt_session_at_rest,
    deserialize_session,
    encrypt_session_at_rest,
    serialize_session,
)


@pytest.fixture
def sample_session() -> RatchetSession:
    shared_key = os.urandom(32)
    bob_initial_dh = X25519PrivateKey.generate()
    bob_pub_bytes = bob_initial_dh.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    alice_dh = X25519PrivateKey.generate()
    session = RatchetSession(
        shared_key=shared_key,
        our_dh_priv=alice_dh,
        their_dh_pub_bytes=bob_pub_bytes,
        is_initiator=True,
    )
    # Encrypt a message to populate state
    session.ratchet_encrypt(b"warmup")
    return session


def test_session_serialization_dict_roundtrip(sample_session: RatchetSession) -> None:
    data = serialize_session(sample_session)
    restored = deserialize_session(data)

    assert restored.rk == sample_session.rk
    assert restored.ns == sample_session.ns
    assert restored.nr == sample_session.nr
    assert restored.pn == sample_session.pn
    assert restored.our_dh_pub_bytes == sample_session.our_dh_pub_bytes
    assert restored.dhr == sample_session.dhr


def test_encrypted_session_at_rest_roundtrip(sample_session: RatchetSession) -> None:
    passphrase = "UltraStrongCorrectPassphrase!123"
    encrypted_blob = encrypt_session_at_rest(sample_session, passphrase)
    assert len(encrypted_blob) > 60

    restored = decrypt_session_at_rest(encrypted_blob, passphrase)
    assert restored.rk == sample_session.rk
    assert restored.ns == sample_session.ns


def test_encrypted_session_wrong_passphrase(sample_session: RatchetSession) -> None:
    encrypted_blob = encrypt_session_at_rest(sample_session, "CorrectPassphrase")
    with pytest.raises(ValueError, match="Decryption failed: incorrect passphrase"):
        decrypt_session_at_rest(encrypted_blob, "WrongPassphrase")


def test_encrypted_session_tampered_blob(sample_session: RatchetSession) -> None:
    encrypted_blob = bytearray(encrypt_session_at_rest(sample_session, "Passphrase"))
    # Corrupt last byte
    encrypted_blob[-1] ^= 0xFF
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_session_at_rest(bytes(encrypted_blob), "Passphrase")


def test_encrypted_session_corrupt_length() -> None:
    with pytest.raises(ValueError, match="Encrypted session data is corrupt"):
        decrypt_session_at_rest(b"short", "pass")
