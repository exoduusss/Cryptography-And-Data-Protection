"""Deterministic Key Schedule for deriving round subkeys from a master key.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import abc

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class BaseKeySchedule(abc.ABC):
    """Abstract base class for Feistel key schedules."""

    @abc.abstractmethod
    def generate_round_keys(self, rounds: int, subkey_bytes: int = 4) -> tuple[int, ...]:
        """Generate a tuple of integer subkeys, one per round."""
        ...


class HKDFKeySchedule(BaseKeySchedule):
    """Cryptographic key schedule using HKDF-SHA256 (RFC 5869).

    Extracts entropy from the master key and expands it into independent,
    cryptographically strong subkeys for each round.
    """

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) < 16:
            raise ValueError(
                f"Master key must be at least 16 bytes (128 bits), got {len(master_key)}"
            )
        self._master_key = master_key

    def generate_round_keys(self, rounds: int, subkey_bytes: int = 4) -> tuple[int, ...]:
        if rounds < 1:
            raise ValueError(f"Number of rounds must be >= 1, got {rounds}")

        total_bytes = rounds * subkey_bytes
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=total_bytes,
            salt=b"feistel-key-schedule-salt-v1",
            info=b"feistel-round-subkeys",
        )
        key_stream = hkdf.derive(self._master_key)

        round_keys = []
        for i in range(rounds):
            chunk = key_stream[i * subkey_bytes : (i + 1) * subkey_bytes]
            sub_int = int.from_bytes(chunk, byteorder="big")
            round_keys.append(sub_int)

        return tuple(round_keys)


class RotationalKeySchedule(BaseKeySchedule):
    """Pedagogical rotational key schedule with round constant addition (DES/Blowfish style)."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) < 16:
            raise ValueError("Master key must be at least 16 bytes (128 bits)")
        self._master_key = master_key

    def generate_round_keys(self, rounds: int, subkey_bytes: int = 4) -> tuple[int, ...]:
        # Split 128-bit key into four 32-bit words
        words = [
            int.from_bytes(self._master_key[i * 4 : (i + 1) * 4], "big")
            for i in range(len(self._master_key) // 4)
        ]

        round_keys: list[int] = []
        golden_ratio_const = 0x9E3779B9  # 2^32 / phi

        for r in range(rounds):
            w_idx = r % len(words)
            word = words[w_idx]
            # Rotate left by (r * 3 + 1) % 32 and add round constant
            shift = (r * 3 + 1) % 32
            rotated = ((word << shift) & 0xFFFFFFFF) | (word >> (32 - shift))
            subkey = (rotated ^ (golden_ratio_const * (r + 1))) & 0xFFFFFFFF
            round_keys.append(subkey)

        return tuple(round_keys)
