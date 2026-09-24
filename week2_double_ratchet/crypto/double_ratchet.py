"""Signal Double Ratchet state machine implementation.

Educational reference implementation adhering to the official Signal Double Ratchet specification.
Uses X25519, HKDF-SHA256, and ChaCha20-Poly1305.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from week2_double_ratchet.crypto.encryption import decrypt_aead, encrypt_aead
from week2_double_ratchet.crypto.kdf import kdf_ck, kdf_rk


@dataclass(frozen=True)
class MessageHeader:
    """Double Ratchet message header transmitted in clear alongside ciphertext."""

    dh_pub: bytes  # 32-byte sender's current ratchet public key
    pn: int  # Previous sending chain length
    n: int  # Message counter in current sending chain

    def to_bytes(self) -> bytes:
        """Serialize header to canonical binary format for authenticated associated data."""
        # Format: 32 bytes dh_pub + 4 bytes pn (big-endian) + 4 bytes n (big-endian) = 40 bytes
        return self.dh_pub + struct.pack(">II", self.pn, self.n)

    @classmethod
    def from_bytes(cls, data: bytes) -> MessageHeader:
        """Deserialize header from 40-byte binary representation."""
        if len(data) != 40:
            raise ValueError(f"Header data must be exactly 40 bytes, got {len(data)}")
        dh_pub = data[:32]
        pn, n = struct.unpack(">II", data[32:40])
        return cls(dh_pub=dh_pub, pn=pn, n=n)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dh_pub": self.dh_pub.hex(),
            "pn": self.pn,
            "n": self.n,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessageHeader:
        return cls(
            dh_pub=bytes.fromhex(data["dh_pub"]),
            pn=int(data["pn"]),
            n=int(data["n"]),
        )


@dataclass(frozen=True)
class RatchetMessage:
    """Complete message packet containing plaintext header and authenticated ciphertext."""

    header: MessageHeader
    ciphertext: bytes  # 12-byte nonce || ciphertext || 16-byte Poly1305 tag

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "ciphertext": self.ciphertext.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RatchetMessage:
        return cls(
            header=MessageHeader.from_dict(data["header"]),
            ciphertext=bytes.fromhex(data["ciphertext"]),
        )


class RatchetSession:
    """Double Ratchet session state machine.

    Maintains Root Key, Sending/Receiving symmetric chains, DH key pairs,
    message counters, and a bounded cache for out-of-order skipped message keys.
    """

    def __init__(
        self,
        shared_key: bytes,
        our_dh_priv: X25519PrivateKey,
        their_dh_pub_bytes: bytes | None = None,
        is_initiator: bool = True,
        max_skip: int = 1000,
    ) -> None:
        self.dhs = our_dh_priv
        self.dhr: bytes | None = their_dh_pub_bytes
        self.rk = shared_key
        self.cks: bytes | None = None
        self.ckr: bytes | None = None
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.max_skip = max_skip
        # Skipped keys: map of (their_dh_pub_bytes, message_number) -> message_key (32 bytes)
        self.mk_skipped: dict[tuple[bytes, int], bytes] = {}

        if is_initiator:
            if their_dh_pub_bytes is None:
                raise ValueError(
                    "Initiator must be provided with recipient's initial DH public key"
                )
            their_pub = X25519PublicKey.from_public_bytes(their_dh_pub_bytes)
            # Initiator immediately performs first DH ratchet step
            dh_secret = self.dhs.exchange(their_pub)
            self.rk, self.cks = kdf_rk(self.rk, dh_secret)

    @property
    def our_dh_pub_bytes(self) -> bytes:
        return self.dhs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def ratchet_encrypt(self, plaintext: bytes, ad_prefix: bytes = b"") -> RatchetMessage:
        """Encrypt a message, advancing the symmetric sending chain.

        Args:
            plaintext: Plaintext bytes.
            ad_prefix: Optional context-specific Associated Data prefix.

        Returns:
            RatchetMessage containing the current header and AEAD ciphertext.
        """
        if self.cks is None:
            raise ValueError("Sending chain is not initialized yet")

        self.cks, mk = kdf_ck(self.cks)
        header = MessageHeader(dh_pub=self.our_dh_pub_bytes, pn=self.pn, n=self.ns)
        self.ns += 1

        associated_data = ad_prefix + header.to_bytes()
        ciphertext = encrypt_aead(mk, plaintext, associated_data)
        return RatchetMessage(header=header, ciphertext=ciphertext)

    def ratchet_decrypt(self, message: RatchetMessage, ad_prefix: bytes = b"") -> bytes:
        """Decrypt an incoming message, handling DH turns and skipped keys.

        Args:
            message: Incoming RatchetMessage packet.
            ad_prefix: Optional context-specific Associated Data prefix.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If message cannot be authenticated, counters exceed bounds,
                        or key has already been consumed.
        """
        associated_data = ad_prefix + message.header.to_bytes()

        # Step 1: Check if this message corresponds to a previously skipped message key
        skipped_key = (message.header.dh_pub, message.header.n)
        if skipped_key in self.mk_skipped:
            mk = self.mk_skipped.pop(skipped_key)
            return decrypt_aead(mk, message.ciphertext, associated_data)

        # Step 2: If a new remote DH ratchet key is received, step the DH ratchet
        if self.dhr != message.header.dh_pub:
            # Skip any missing messages in the current receiving chain
            self._skip_message_keys(until=message.header.pn)
            self._dh_ratchet(message.header.dh_pub)

        # Step 3: Skip any missing messages in the new receiving chain up to message.header.n
        self._skip_message_keys(until=message.header.n)

        # Step 4: Advance receiving chain for this message
        if self.ckr is None:
            raise ValueError("Receiving chain key is not set")

        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1

        return decrypt_aead(mk, message.ciphertext, associated_data)

    def _skip_message_keys(self, until: int) -> None:
        """Cache skipped keys in the current receiving chain up to target index."""
        if self.ckr is None:
            return

        if self.nr + self.max_skip < until:
            raise ValueError(f"Too many skipped messages ({until - self.nr} > {self.max_skip})")

        while self.nr < until:
            if len(self.mk_skipped) >= self.max_skip:
                raise ValueError(f"Skipped keys storage limit reached ({self.max_skip})")
            if self.dhr is None:
                break
            self.ckr, mk = kdf_ck(self.ckr)
            self.mk_skipped[(self.dhr, self.nr)] = mk
            self.nr += 1

    def _dh_ratchet(self, their_new_dh_pub_bytes: bytes) -> None:
        """Perform a full Diffie-Hellman ratchet turn."""
        their_pub = X25519PublicKey.from_public_bytes(their_new_dh_pub_bytes)
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr = their_new_dh_pub_bytes

        # Derive receiving chain key using current our_dh_priv and their new DH key
        dh_recv = self.dhs.exchange(their_pub)
        self.rk, self.ckr = kdf_rk(self.rk, dh_recv)

        # Generate fresh our_dh_priv and derive new sending chain key
        self.dhs = X25519PrivateKey.generate()
        dh_send = self.dhs.exchange(their_pub)
        self.rk, self.cks = kdf_rk(self.rk, dh_send)
