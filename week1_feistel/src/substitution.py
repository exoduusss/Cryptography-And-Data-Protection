"""Substitution Box (S-Box) implementations and cryptanalytic property analyzers.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import abc
from typing import Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Standard Rijndael / AES 8-bit S-Box table
RIJNDAEL_SBOX: tuple[int, ...] = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)


class BaseSBox(abc.ABC):
    """Abstract base class representing an 8-bit S-Box mapping."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the S-box strategy."""
        ...

    @abc.abstractmethod
    def substitute(self, byte_val: int) -> int:
        """Substitute an 8-bit integer into its S-box image."""
        ...

    @property
    @abc.abstractmethod
    def table(self) -> Sequence[int]:
        """Return the underlying 256-element substitution lookup table."""
        ...


class FixedSBox(BaseSBox):
    """Fixed non-linear S-Box based on the Rijndael / AES affine transformation."""

    def __init__(self, table: Sequence[int] = RIJNDAEL_SBOX) -> None:
        if len(table) != 256:
            raise ValueError(f"S-Box table must have 256 elements, got {len(table)}")
        self._table = tuple(table)

    @property
    def name(self) -> str:
        return "fixed_rijndael"

    def substitute(self, byte_val: int) -> int:
        return self._table[byte_val & 0xFF]

    @property
    def table(self) -> Sequence[int]:
        return self._table


class KeyDependentSBox(BaseSBox):
    """Key-dependent S-Box constructed dynamically via key material and Fisher-Yates shuffle."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) < 16:
            raise ValueError("Master key must be at least 16 bytes for key-dependent S-box")
        self._table = self._generate_table(master_key)

    @property
    def name(self) -> str:
        return "key_dependent"

    @property
    def table(self) -> Sequence[int]:
        return self._table

    def substitute(self, byte_val: int) -> int:
        return self._table[byte_val & 0xFF]

    def _generate_table(self, master_key: bytes) -> tuple[int, ...]:
        # Derive 512 pseudorandom bytes via HKDF-SHA256 for deterministic Fisher-Yates shuffle
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=512,
            salt=b"key-dependent-sbox-salt",
            info=b"sbox-generation",
        )
        stream = hkdf.derive(master_key)

        table = list(range(256))
        for i in range(255, 0, -1):
            # Select uniform index in [0, i]
            rand_val = (stream[i * 2] << 8 | stream[i * 2 + 1]) % (i + 1)
            table[i], table[rand_val] = table[rand_val], table[i]

        return tuple(table)


class CustomAffineSBox(BaseSBox):
    """Custom documented design: Non-linear power map x^7 with affine shift
    and bijective correction.

    Design rationale:
    Over GF(2^8), x |-> x^7 provides non-linear algebraic degree 3.
    We compute (x^7 ^ 0x63) % 256, then resolve collisions deterministically
    to ensure strict bijectivity while preserving high algebraic complexity.
    """

    def __init__(self) -> None:
        self._table = self._build_sbox()

    @property
    def name(self) -> str:
        return "custom_hybrid"

    @property
    def table(self) -> Sequence[int]:
        return self._table

    def substitute(self, byte_val: int) -> int:
        return self._table[byte_val & 0xFF]

    def _build_sbox(self) -> tuple[int, ...]:
        # Generate initial candidate table via x^7 ^ 0x63
        raw = [(pow(x, 7, 257) ^ 0x63) % 256 for x in range(256)]
        seen: set[int] = set()
        missing = [v for v in range(256) if v not in raw]
        repaired = []
        for val in raw:
            if val not in seen:
                seen.add(val)
                repaired.append(val)
            else:
                replacement = missing.pop(0)
                seen.add(replacement)
                repaired.append(replacement)
        return tuple(repaired)


# Cryptanalytic metric analysis functions


def is_bijective(sbox: Sequence[int]) -> bool:
    """Verify whether an S-box defines a bijective mapping (permutation of 0..255)."""
    return len(sbox) == 256 and set(sbox) == set(range(256))


def compute_differential_distribution_table(sbox: Sequence[int]) -> list[list[int]]:
    """Compute the 256x256 Difference Distribution Table (DDT) of an 8-bit S-Box.

    DDT[dx][dy] = count of x such that S(x) ^ S(x ^ dx) == dy
    """
    ddt = [[0] * 256 for _ in range(256)]
    for dx in range(256):
        for x in range(256):
            dy = sbox[x] ^ sbox[x ^ dx]
            ddt[dx][dy] += 1
    return ddt


def differential_uniformity(sbox: Sequence[int]) -> int:
    """Compute the differential uniformity delta: max DDT[dx][dy] for dx != 0."""
    max_val = 0
    for dx in range(1, 256):
        counts = [0] * 256
        for x in range(256):
            dy = sbox[x] ^ sbox[x ^ dx]
            counts[dy] += 1
        local_max = max(counts)
        if local_max > max_val:
            max_val = local_max
    return max_val


def compute_nonlinearity(sbox: Sequence[int]) -> int:
    """Compute the Walsh-Hadamard nonlinearity of an 8-bit S-Box.

    Nonlinearity measures the minimum Hamming distance between any non-zero linear
    combination of the S-box coordinate functions and the set of all affine functions.
    NL(S) = 128 - (1/2) * max_{a, b != 0} |W_b(a)|
    """
    max_walsh = 0

    # Test all non-zero output linear combinations b in 1..255
    for b in range(1, 256):
        # Construct truth table for coordinate function f(x) = parity(b & S(x))
        # Represent as +/- 1: (-1)^f(x)
        f = [1 - 2 * (bin(b & sbox[x]).count("1") % 2) for x in range(256)]

        # Fast Walsh-Hadamard Transform (FWHT) in place
        h = 1
        while h < 256:
            for i in range(0, 256, h * 2):
                for j in range(i, i + h):
                    x_val = f[j]
                    y_val = f[j + h]
                    f[j] = x_val + y_val
                    f[j + h] = x_val - y_val
            h *= 2

        # Find maximum absolute Walsh coefficient for this b
        cur_max = max(abs(coeff) for coeff in f)
        if cur_max > max_walsh:
            max_walsh = cur_max

    return 128 - (max_walsh // 2)
