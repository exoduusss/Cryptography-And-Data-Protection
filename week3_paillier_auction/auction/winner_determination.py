"""Winner and clearing price determination for sealed-bid homomorphic auctions.

Educational reference implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from week3_paillier_auction.auction.bid import PriceLadder


@dataclass(frozen=True)
class AuctionResult:
    """Outcome of auction winner determination."""

    clearing_price: int | None
    winning_level_index: int | None
    demand_at_clearing_price: int
    is_tie: bool
    pricing_rule: str
    decrypted_tallies: tuple[int, ...]


def determine_winner(
    price_ladder: PriceLadder,
    decrypted_tallies: Sequence[int],
    pricing_rule: str = "first_price",
) -> AuctionResult:
    """Determine the winning price level and demand from decrypted aggregate tallies.

    Args:
        price_ladder: The discrete price ladder used in the auction.
        decrypted_tallies: Sequence of integer counts corresponding to each price level.
        pricing_rule: 'first_price' or 'second_price' (Vickrey).

    Returns:
        AuctionResult summarizing the clearing price and outcome.

    Raises:
        ValueError: If tallies length does not match price ladder.
    """
    if len(decrypted_tallies) != len(price_ladder):
        raise ValueError(
            f"Tallies length ({len(decrypted_tallies)}) does not match "
            f"price ladder ({len(price_ladder)})"
        )

    tallies_tuple = tuple(decrypted_tallies)

    # 1. Check if any bids were placed (total bids at lowest price level >= 1)
    if not any(t > 0 for t in decrypted_tallies):
        return AuctionResult(
            clearing_price=None,
            winning_level_index=None,
            demand_at_clearing_price=0,
            is_tie=False,
            pricing_rule=pricing_rule,
            decrypted_tallies=tallies_tuple,
        )

    # 2. Find highest price level with demand >= 1
    highest_idx: int | None = None
    for idx in range(len(price_ladder) - 1, -1, -1):
        if decrypted_tallies[idx] >= 1:
            highest_idx = idx
            break

    if highest_idx is None:
        return AuctionResult(
            clearing_price=None,
            winning_level_index=None,
            demand_at_clearing_price=0,
            is_tie=False,
            pricing_rule=pricing_rule,
            decrypted_tallies=tallies_tuple,
        )

    top_demand = decrypted_tallies[highest_idx]
    is_tie = top_demand > 1

    clean_rule = pricing_rule.lower().strip()

    if clean_rule in ("first_price", "first-price"):
        clearing_price = price_ladder[highest_idx]
        return AuctionResult(
            clearing_price=clearing_price,
            winning_level_index=highest_idx,
            demand_at_clearing_price=top_demand,
            is_tie=is_tie,
            pricing_rule="first_price",
            decrypted_tallies=tallies_tuple,
        )

    elif clean_rule in ("second_price", "second-price", "vickrey"):
        if is_tie:
            # If two or more bidders tied at top level, second price equals top price
            clearing_price = price_ladder[highest_idx]
        else:
            # Find next highest price level with demand >= 2
            second_idx: int | None = None
            for idx in range(highest_idx - 1, -1, -1):
                if decrypted_tallies[idx] >= 2:
                    second_idx = idx
                    break
            clearing_price = price_ladder[second_idx] if second_idx is not None else price_ladder[0]

        return AuctionResult(
            clearing_price=clearing_price,
            winning_level_index=highest_idx,
            demand_at_clearing_price=top_demand,
            is_tie=is_tie,
            pricing_rule="second_price",
            decrypted_tallies=tallies_tuple,
        )

    else:
        raise ValueError(f"Unsupported rule '{pricing_rule}'. Valid: 'first_price', 'second_price'")
