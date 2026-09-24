"""Identity keys, Prekeys, and Prekey bundles for X3DH and Double Ratchet.

Educational reference implementation. Uses vetted primitives from `cryptography`.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


@dataclass(frozen=True)
class PreKeyBundle:
    """Public prekey bundle uploaded to the untrusted server for initial key agreement."""

    user_id: str
    identity_dh_pub: bytes  # 32-byte X25519 public key
    identity_sign_pub: bytes  # 32-byte Ed25519 public key
    signed_prekey_pub: bytes  # 32-byte X25519 public key
    signed_prekey_sig: bytes  # 64-byte Ed25519 signature over signed_prekey_pub
    one_time_prekey_pub: bytes | None = None  # Optional 32-byte X25519 public key

    def verify_signature(self) -> bool:
        """Verify that the signed prekey is authentically signed by the identity signing key."""
        try:
            sign_key = Ed25519PublicKey.from_public_bytes(self.identity_sign_pub)
            sign_key.verify(self.signed_prekey_sig, self.signed_prekey_pub)
            return True
        except (InvalidSignature, ValueError):
            return False


class IdentityKeyPair:
    """Container holding a participant's long-term cryptographic identities."""

    def __init__(
        self,
        user_id: str,
        dh_priv: X25519PrivateKey | None = None,
        sign_priv: Ed25519PrivateKey | None = None,
    ) -> None:
        self.user_id = user_id
        self.dh_priv: X25519PrivateKey = (
            dh_priv if dh_priv is not None else X25519PrivateKey.generate()
        )
        self.sign_priv: Ed25519PrivateKey = (
            sign_priv if sign_priv is not None else Ed25519PrivateKey.generate()
        )

    @property
    def dh_pub(self) -> X25519PublicKey:
        return self.dh_priv.public_key()

    @property
    def sign_pub(self) -> Ed25519PublicKey:
        return self.sign_priv.public_key()

    @property
    def dh_pub_bytes(self) -> bytes:
        return self.dh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def sign_pub_bytes(self) -> bytes:
        return self.sign_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the Ed25519 identity key."""
        return self.sign_priv.sign(message)

    def create_signed_prekey(self) -> tuple[X25519PrivateKey, bytes, bytes]:
        """Generate a signed prekey pair and its Ed25519 signature.

        Returns:
            Tuple of (private_key, public_bytes, signature_bytes).
        """
        spk_priv = X25519PrivateKey.generate()
        spk_pub_bytes = spk_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sig = self.sign(spk_pub_bytes)
        return spk_priv, spk_pub_bytes, sig

    def create_one_time_prekeys(self, count: int = 10) -> list[tuple[X25519PrivateKey, bytes]]:
        """Generate a batch of one-time X25519 prekeys."""
        keys = []
        for _ in range(count):
            priv = X25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            keys.append((priv, pub_bytes))
        return keys
