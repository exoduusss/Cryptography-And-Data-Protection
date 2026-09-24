"""Round function implementations for the Feistel cipher.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import abc

from week1_feistel.src.permutation import DEFAULT_P32, PermutationBox
from week1_feistel.src.substitution import BaseSBox, FixedSBox
from week1_feistel.src.utils import rot_left


class BaseRoundFunction(abc.ABC):
    """Abstract interface for a Feistel round function F(R, K)."""

    @abc.abstractmethod
    def evaluate(self, right_half: int, round_key: int) -> int:
        """Evaluate the round function on half-block integer R with round key K."""
        ...


class SPNRoundFunction(BaseRoundFunction):
    """Substitution-Permutation Network (SPN) style round function.

    Steps:
    1. Key addition: T = R ^ K (mod 2^32)
    2. Byte Substitution: 4 parallel S-Box substitutions
    3. Bitwise Permutation: P-Box bit diffusion
    """

    def __init__(
        self,
        sbox: BaseSBox | None = None,
        pbox: PermutationBox | None = None,
    ) -> None:
        self.sbox = sbox if sbox is not None else FixedSBox()
        self.pbox = pbox if pbox is not None else PermutationBox(DEFAULT_P32)

    def evaluate(self, right_half: int, round_key: int) -> int:
        # Step 1: Key addition
        mixed = (right_half ^ round_key) & 0xFFFFFFFF

        # Step 2: S-Box substitution on each 8-bit byte
        b0 = (mixed >> 24) & 0xFF
        b1 = (mixed >> 16) & 0xFF
        b2 = (mixed >> 8) & 0xFF
        b3 = mixed & 0xFF

        s0 = self.sbox.substitute(b0)
        s1 = self.sbox.substitute(b1)
        s2 = self.sbox.substitute(b2)
        s3 = self.sbox.substitute(b3)

        substituted = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3

        # Step 3: P-Box permutation
        return self.pbox.permute(substituted)


class ARXRoundFunction(BaseRoundFunction):
    """Alternative ARX (Addition-Rotation-XOR) hybrid round function with S-Box."""

    def __init__(self, sbox: BaseSBox | None = None) -> None:
        self.sbox = sbox if sbox is not None else FixedSBox()

    def evaluate(self, right_half: int, round_key: int) -> int:
        # Modular addition with round key
        a = (right_half + round_key) & 0xFFFFFFFF
        # Non-linear byte substitution
        b0 = self.sbox.substitute((a >> 24) & 0xFF)
        b1 = self.sbox.substitute((a >> 16) & 0xFF)
        b2 = self.sbox.substitute((a >> 8) & 0xFF)
        b3 = self.sbox.substitute(a & 0xFF)
        s = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        # Circular rotation and mixing
        return rot_left(s, 11, 32) ^ rot_left(s, 21, 32)
