"""Data models for discrete price ladders and encrypted bid vectors.

Educational reference implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class PriceLadder:
    """Discrete, strictly increasing price ladder for sealed-bid auctions."""

    levels: tuple[int, ...]

    def __init__(self, levels: Sequence[int]) -> None:
        if not levels:
            raise ValueError("Price ladder must contain at least one price level")
        sorted_levels = tuple(sorted(levels))
        if len(set(sorted_levels)) != len(sorted_levels):
            raise ValueError("Price ladder levels must be unique")
        object.__setattr__(self, "levels", sorted_levels)

    def __len__(self) -> int:
        return len(self.levels)

    def __getitem__(self, index: int) -> int:
        return self.levels[index]

    @property
    def min_price(self) -> int:
        return self.levels[0]

    @property
    def max_price(self) -> int:
        return self.levels[-1]

    def index_of(self, price: int) -> int:
        """Return the ladder index of an exact price."""
        try:
            return self.levels.index(price)
        except ValueError as e:
            raise ValueError(f"Price {price} is not on the price ladder: {self.levels}") from e


@dataclass(frozen=True)
class BidVector:
    """Encrypted indicator vector submitted by a bidder."""

    bidder_id: str
    encrypted_indicators: tuple[int, ...]
    is_cumulative: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "bidder_id": self.bidder_id,
            "encrypted_indicators": [hex(c) for c in self.encrypted_indicators],
            "is_cumulative": self.is_cumulative,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BidVector:
        return cls(
            bidder_id=data["bidder_id"],
            encrypted_indicators=tuple(int(c, 16) for c in data["encrypted_indicators"]),
            is_cumulative=data.get("is_cumulative", True),
        )
