"""Bidder entity that constructs and encrypts bid vectors over a price ladder.

Educational reference implementation.
"""

from __future__ import annotations

from week3_paillier_auction.auction.bid import BidVector, PriceLadder
from week3_paillier_auction.crypto.paillier import PaillierPublicKey


class Bidder:
    """Participant in a sealed-bid homomorphic auction."""

    def __init__(
        self,
        bidder_id: str,
        public_key: PaillierPublicKey,
        price_ladder: PriceLadder,
    ) -> None:
        self.bidder_id = bidder_id
        self.public_key = public_key
        self.price_ladder = price_ladder

    def create_bid(self, bid_amount: int, cumulative: bool = True) -> BidVector:
        """Create an encrypted bid vector for a specified bid amount.

        Args:
            bid_amount: Chosen bid amount (must be in range [min_price, max_price]).
            cumulative: If True, uses cumulative encoding (v_j = 1 for p_j <= bid).
                        If False, uses one-hot encoding (v_j = 1 for exact match).

        Returns:
            BidVector containing Paillier ciphertexts.

        Raises:
            ValueError: If bid_amount is outside price ladder boundaries.
        """
        if bid_amount < self.price_ladder.min_price or bid_amount > self.price_ladder.max_price:
            raise ValueError(
                f"Bid amount {bid_amount} is outside price ladder range "
                f"[{self.price_ladder.min_price}, {self.price_ladder.max_price}]"
            )

        indicators: list[int] = []
        for level in self.price_ladder.levels:
            if cumulative:
                val = 1 if level <= bid_amount else 0
            else:
                val = 1 if level == bid_amount else 0
            indicators.append(val)

        # Encrypt each component with public key
        encrypted_components = tuple(self.public_key.encrypt(v) for v in indicators)
        return BidVector(
            bidder_id=self.bidder_id,
            encrypted_indicators=encrypted_components,
            is_cumulative=cumulative,
        )
