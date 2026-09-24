"""Independent Trustee entity that holds the private key and decrypts aggregate tallies.

Educational reference implementation. The trustee NEVER decrypts individual bids.
"""

from __future__ import annotations

from typing import Sequence

from week3_paillier_auction.crypto.paillier import PaillierPrivateKey


class Trustee:
    """Trustee holding the Paillier private key for secure multi-party decryption."""

    def __init__(self, private_key: PaillierPrivateKey) -> None:
        self.private_key = private_key

    def decrypt_aggregate_tally(self, aggregated_ciphertexts: Sequence[int]) -> tuple[int, ...]:
        """Decrypt ONLY the aggregated ciphertext tally vector.

        Args:
            aggregated_ciphertexts: Vector of homomorphically tallied ciphertexts.

        Returns:
            Tuple of plaintext integer counts for each price level.
        """
        return tuple(self.private_key.decrypt(c) for c in aggregated_ciphertexts)
