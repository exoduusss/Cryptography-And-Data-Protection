"""Core Feistel Cipher implementation.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

from week1_feistel.src.key_schedule import BaseKeySchedule, HKDFKeySchedule
from week1_feistel.src.round_function import BaseRoundFunction, SPNRoundFunction
from week1_feistel.src.utils import join_halves, split_halves


class FeistelCipher:
    """Configurable Feistel Block Cipher.

    Defaults:
        - Block size: 64 bits (8 bytes)
        - Key size: 128 bits (16 bytes)
        - Rounds: 16
    """

    def __init__(
        self,
        key: bytes,
        rounds: int = 16,
        round_function: BaseRoundFunction | None = None,
        key_schedule: BaseKeySchedule | None = None,
        block_size: int = 8,
    ) -> None:
        if block_size != 8:
            raise ValueError(f"Block size must be 8-byte (64-bit), got {block_size}")
        if len(key) < 16:
            raise ValueError(
                f"Master key must be at least 16 bytes (128 bits), got {len(key)} bytes"
            )
        if rounds < 1:
            raise ValueError(f"Rounds must be at least 1, got {rounds}")

        self.block_size = block_size
        self.rounds = rounds
        self.key = key
        self.half_size = block_size // 2

        self.round_function: BaseRoundFunction = (
            round_function if round_function is not None else SPNRoundFunction()
        )
        self.key_schedule: BaseKeySchedule = (
            key_schedule if key_schedule is not None else HKDFKeySchedule(key)
        )

        self.round_keys = self.key_schedule.generate_round_keys(
            rounds=self.rounds, subkey_bytes=self.half_size
        )

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single block using the Feistel network.

        Args:
            block: Plaintext block of exactly self.block_size bytes.

        Returns:
            Ciphertext block of self.block_size bytes.
        """
        if len(block) != self.block_size:
            raise ValueError(
                f"Block length must be {self.block_size} bytes, got {len(block)} bytes"
            )

        left, right = split_halves(block)

        for i in range(self.rounds):
            f_out = self.round_function.evaluate(right, self.round_keys[i])
            left, right = right, left ^ f_out

        # Final swap: (R_r, L_r)
        return join_halves(right, left, self.half_size)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single block by executing the Feistel network with reversed round keys.

        Args:
            block: Ciphertext block of exactly self.block_size bytes.

        Returns:
            Decrypted plaintext block of self.block_size bytes.
        """
        if len(block) != self.block_size:
            raise ValueError(
                f"Block length must be {self.block_size} bytes, got {len(block)} bytes"
            )

        left, right = split_halves(block)

        # Decryption runs the exact same Feistel logic with reversed round subkeys
        for i in range(self.rounds - 1, -1, -1):
            f_out = self.round_function.evaluate(right, self.round_keys[i])
            left, right = right, left ^ f_out

        # Final swap
        return join_halves(right, left, self.half_size)

    def encrypt_block_with_rounds(self, block: bytes) -> list[bytes]:
        """Encrypt block while recording the intermediate state after each round.

        Returns a list of length rounds + 1 (initial state + state after each round).
        Used for avalanche testing and cryptanalytic visualization.
        """
        if len(block) != self.block_size:
            raise ValueError(
                f"Block length must be {self.block_size} bytes, got {len(block)} bytes"
            )

        states: list[bytes] = [block]
        left, right = split_halves(block)

        for i in range(self.rounds):
            f_out = self.round_function.evaluate(right, self.round_keys[i])
            left, right = right, left ^ f_out
            # Intermediate state with standard half representation
            states.append(join_halves(left, right, self.half_size))

        # Adjust the final state to match the post-swap output
        states[-1] = join_halves(right, left, self.half_size)
        return states
