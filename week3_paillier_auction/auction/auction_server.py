"""Untrusted Auctioneer server that collects and homomorphically tallies encrypted bids.

Educational reference implementation. The auctioneer holds ONLY the public key.
"""

from __future__ import annotations

from week3_paillier_auction.auction.bid import BidVector, PriceLadder
from week3_paillier_auction.crypto.paillier import PaillierPublicKey


class AuctionServer:
    """Untrusted auctioneer that orchestrates bidding and computes homomorphic tallies."""

    def __init__(
        self,
        public_key: PaillierPublicKey,
        price_ladder: PriceLadder,
    ) -> None:
        self.public_key = public_key
        self.price_ladder = price_ladder
        self.registered_bidders: set[str] = set()
        self.received_bids: list[BidVector] = []

    def submit_bid(self, bid: BidVector) -> None:
        """Submit an encrypted bid vector to the auction.

        Args:
            bid: BidVector from a bidder.

        Raises:
            ValueError: If bidder ID is duplicated or vector dimension does not match ladder.
        """
        if bid.bidder_id in self.registered_bidders:
            raise ValueError(f"Duplicate bidder ID rejected: '{bid.bidder_id}' has already bid")
        if len(bid.encrypted_indicators) != len(self.price_ladder):
            raise ValueError(
                f"Bid vector length ({len(bid.encrypted_indicators)}) does not match "
                f"price ladder dimensions ({len(self.price_ladder)})"
            )

        self.registered_bidders.add(bid.bidder_id)
        self.received_bids.append(bid)

    def tally_bids(self) -> tuple[int, ...]:
        """Compute the component-wise homomorphic sum of all submitted bid vectors.

        Returns:
            Tuple of aggregated ciphertexts [C_0, C_1, ..., C_{K-1}].
        """
        ladder_len = len(self.price_ladder)

        # If no bids received, return fresh encryptions of 0
        if not self.received_bids:
            return tuple(self.public_key.encrypt(0) for _ in range(ladder_len))

        # Multiply component-wise modulo n^2
        tallies: list[int] = []
        for j in range(ladder_len):
            col_prod = 1
            for b in self.received_bids:
                col_prod = self.public_key.homomorphic_add(col_prod, b.encrypted_indicators[j])
            tallies.append(col_prod)

        return tuple(tallies)
