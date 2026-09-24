"""Unit tests for AEAD ChaCha20-Poly1305 encryption with Associated Data."""

from __future__ import annotations

import os

import pytest

from week2_double_ratchet.crypto.encryption import decrypt_aead, encrypt_aead


def test_aead_roundtrip() -> None:
    key = os.urandom(32)
    plaintext = b"Top secret cryptographic message payload"
    ad = b"header_metadata_v1"

    ct = encrypt_aead(key, plaintext, ad)
    assert ct != plaintext
    assert len(ct) >= 12 + len(plaintext) + 16

    dec = decrypt_aead(key, ct, ad)
    assert dec == plaintext


def test_aead_tampered_ciphertext() -> None:
    key = os.urandom(32)
    plaintext = b"Unmodified message"
    ad = b"valid_associated_data"

    ct = bytearray(encrypt_aead(key, plaintext, ad))
    # Invert a single bit in the ciphertext portion
    ct[15] ^= 0x01

    with pytest.raises(ValueError, match="AEAD authentication failed"):
        decrypt_aead(key, bytes(ct), ad)


def test_aead_tampered_associated_data() -> None:
    key = os.urandom(32)
    plaintext = b"Authenticated payload"
    ad_legit = b"legit_header_n_1"
    ad_fake = b"fake_header_n_2"

    ct = encrypt_aead(key, plaintext, ad_legit)

    with pytest.raises(ValueError, match="AEAD authentication failed"):
        decrypt_aead(key, ct, ad_fake)


def test_aead_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="Message key must be 32 bytes"):
        encrypt_aead(b"short_key", b"data", b"ad")

    with pytest.raises(ValueError, match="Message key must be 32 bytes"):
        decrypt_aead(b"short_key", b"data" * 10, b"ad")

    with pytest.raises(ValueError, match="Ciphertext too short"):
        decrypt_aead(os.urandom(32), b"too_short", b"ad")
