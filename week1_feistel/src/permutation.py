"""Permutation Box (P-Box) for bitwise linear diffusion.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

from typing import Sequence

# 32-bit diffusion permutation table: maps each bit position [0..31]
# to ensure each S-Box output bit spreads into different S-Boxes in subsequent rounds.
DEFAULT_P32: tuple[int, ...] = (
    0,
    8,
    16,
    24,
    1,
    9,
    17,
    25,
    2,
    10,
    18,
    26,
    3,
    11,
    19,
    27,
    4,
    12,
    20,
    28,
    5,
    13,
    21,
    29,
    6,
    14,
    22,
    30,
    7,
    15,
    23,
    31,
)


class PermutationBox:
    """Permutation box mapping an integer of given bit width through a permutation table."""

    def __init__(self, table: Sequence[int] = DEFAULT_P32, bit_width: int = 32) -> None:
        if len(table) != bit_width:
            raise ValueError(f"Permutation table must have {bit_width} elements, got {len(table)}")
        if set(table) != set(range(bit_width)):
            raise ValueError(f"Permutation table must be a permutation of 0..{bit_width - 1}")
        self._table = tuple(table)
        self._bit_width = bit_width

    @property
    def bit_width(self) -> int:
        return self._bit_width

    def permute(self, value: int) -> int:
        """Permute bits of value according to the permutation table.

        Bit 0 is the most significant bit (MSB), bit width - 1 is LSB.
        """
        out = 0
        for dest_idx, src_idx in enumerate(self._table):
            # Extract src bit from value (0-indexed from MSB)
            shift = self._bit_width - 1 - src_idx
            bit = (value >> shift) & 1
            # Place bit into dest position (0-indexed from MSB)
            out |= bit << (self._bit_width - 1 - dest_idx)
        return out
