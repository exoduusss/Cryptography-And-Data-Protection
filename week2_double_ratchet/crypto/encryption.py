"""AEAD encryption and decryption routines using ChaCha20-Poly1305.

Educational reference implementation. Uses RFC 8439 ChaCha20Poly1305 from `cryptography`.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt_aead(message_key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Encrypt plaintext using ChaCha20-Poly1305 with authenticated associated data.

    Args:
        message_key: 32-byte symmetric message key derived from chain KDF.
        plaintext: Plaintext bytes to encrypt.
        associated_data: Additional authenticated data (e.g., serialized message header).

    Returns:
        12-byte nonce || ciphertext with appended 16-byte Poly1305 tag.
    """
    if len(message_key) != 32:
        raise ValueError(f"Message key must be 32 bytes, got {len(message_key)}")

    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(message_key)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt_aead(message_key: bytes, ciphertext_with_nonce: bytes, associated_data: bytes) -> bytes:
    """Decrypt and verify ciphertext using ChaCha20-Poly1305 with associated data.

    Args:
        message_key: 32-byte symmetric message key.
        ciphertext_with_nonce: 12-byte nonce prepended to ciphertext + tag.
        associated_data: Associated data that must match during authentication.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If ciphertext is too short or authentication tag check fails (tampering).
    """
    if len(message_key) != 32:
        raise ValueError(f"Message key must be 32 bytes, got {len(message_key)}")
    if len(ciphertext_with_nonce) < 12 + 16:
        raise ValueError(
            f"Ciphertext too short (minimum 28 bytes), got {len(ciphertext_with_nonce)}"
        )

    nonce = ciphertext_with_nonce[:12]
    ciphertext = ciphertext_with_nonce[12:]

    aead = ChaCha20Poly1305(message_key)
    try:
        return aead.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as e:
        raise ValueError(
            "AEAD authentication failed: ciphertext or associated data tampered"
        ) from e
