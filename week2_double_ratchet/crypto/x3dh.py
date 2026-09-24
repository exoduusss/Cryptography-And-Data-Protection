"""Extended Triple Diffie-Hellman (X3DH) key agreement protocol implementation.

Educational reference implementation adhering to the Signal X3DH specification.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from week2_double_ratchet.crypto.identity import IdentityKeyPair, PreKeyBundle


def x3dh_initiator(
    alice_identity: IdentityKeyPair,
    bob_bundle: PreKeyBundle,
) -> tuple[bytes, bytes, bytes | None]:
    """Execute the initiator (Alice) side of the X3DH key agreement.

    Args:
        alice_identity: Alice's IdentityKeyPair.
        bob_bundle: Bob's published PreKeyBundle retrieved from the relay.

    Returns:
        Tuple of (shared_master_secret, alice_ephemeral_pub_bytes, used_one_time_prekey_pub).

    Raises:
        ValueError: If Bob's prekey bundle signature fails verification.
    """
    if not bob_bundle.verify_signature():
        raise ValueError("Bob's signed prekey signature is invalid!")

    bob_ik_dh = X25519PublicKey.from_public_bytes(bob_bundle.identity_dh_pub)
    bob_spk = X25519PublicKey.from_public_bytes(bob_bundle.signed_prekey_pub)

    # Alice generates ephemeral X25519 key
    alice_ek = X25519PrivateKey.generate()
    alice_ek_pub_bytes = alice_ek.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Perform DH agreements
    dh1 = alice_identity.dh_priv.exchange(bob_spk)
    dh2 = alice_ek.exchange(bob_ik_dh)
    dh3 = alice_ek.exchange(bob_spk)

    dh_concat = dh1 + dh2 + dh3

    used_opk_pub: bytes | None = None
    if bob_bundle.one_time_prekey_pub is not None:
        bob_opk = X25519PublicKey.from_public_bytes(bob_bundle.one_time_prekey_pub)
        dh4 = alice_ek.exchange(bob_opk)
        dh_concat += dh4
        used_opk_pub = bob_bundle.one_time_prekey_pub

    # Derive master secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=b"X3DH-Master-Secret-v1",
    )
    master_secret = hkdf.derive(dh_concat)
    return master_secret, alice_ek_pub_bytes, used_opk_pub


def x3dh_receiver(
    bob_identity: IdentityKeyPair,
    bob_signed_prekey_priv: X25519PrivateKey,
    bob_one_time_privs: dict[bytes, X25519PrivateKey],
    alice_identity_dh_pub: bytes,
    alice_ephemeral_pub: bytes,
    used_one_time_pub: bytes | None = None,
) -> bytes:
    """Execute the receiver (Bob) side of the X3DH key agreement.

    Args:
        bob_identity: Bob's IdentityKeyPair.
        bob_signed_prekey_priv: Bob's private signed prekey.
        bob_one_time_privs: Map of public_bytes -> private key for Bob's one-time prekeys.
        alice_identity_dh_pub: Alice's X25519 identity public key bytes.
        alice_ephemeral_pub: Alice's ephemeral X25519 public key bytes.
        used_one_time_pub: The one-time prekey public bytes Alice consumed (if any).

    Returns:
        Derived 32-byte shared master secret matching Alice's secret.

    Raises:
        ValueError: If a specified one-time prekey is unknown or already consumed.
    """
    alice_ik_dh = X25519PublicKey.from_public_bytes(alice_identity_dh_pub)
    alice_ek = X25519PublicKey.from_public_bytes(alice_ephemeral_pub)

    dh1 = bob_signed_prekey_priv.exchange(alice_ik_dh)
    dh2 = bob_identity.dh_priv.exchange(alice_ek)
    dh3 = bob_signed_prekey_priv.exchange(alice_ek)

    dh_concat = dh1 + dh2 + dh3

    if used_one_time_pub is not None:
        if used_one_time_pub not in bob_one_time_privs:
            raise ValueError(f"One-time prekey {used_one_time_pub.hex()[:8]} not found or consumed")
        opk_priv = bob_one_time_privs.pop(used_one_time_pub)
        dh4 = opk_priv.exchange(alice_ek)
        dh_concat += dh4

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=b"X3DH-Master-Secret-v1",
    )
    return hkdf.derive(dh_concat)
