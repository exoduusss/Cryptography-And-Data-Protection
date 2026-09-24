"""Unit tests for sealed-bid homomorphic auction protocol, ties, and edge cases."""

from __future__ import annotations

import pytest

from week3_paillier_auction.auction.auction_server import AuctionServer
from week3_paillier_auction.auction.bid import BidVector, PriceLadder
from week3_paillier_auction.auction.bidder import Bidder
from week3_paillier_auction.auction.trustee import Trustee
from week3_paillier_auction.auction.winner_determination import determine_winner
from week3_paillier_auction.crypto.paillier import (
    PaillierPrivateKey,
    PaillierPublicKey,
    generate_paillier_keypair,
)


@pytest.fixture(scope="session")
def setup_auction_env() -> tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder]:
    pub, priv = generate_paillier_keypair(key_size=512)
    ladder = PriceLadder([100, 200, 300, 400, 500, 600, 700])
    return pub, priv, ladder


def test_standard_auction_flow(
    setup_auction_env: tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder],
) -> None:
    pub, priv, ladder = setup_auction_env
    server = AuctionServer(pub, ladder)
    trustee = Trustee(priv)

    # Alice bids 300, Bob bids 500, Charlie bids 400
    b_alice = Bidder("alice", pub, ladder).create_bid(300)
    b_bob = Bidder("bob", pub, ladder).create_bid(500)
    b_charlie = Bidder("charlie", pub, ladder).create_bid(400)

    server.submit_bid(b_alice)
    server.submit_bid(b_bob)
    server.submit_bid(b_charlie)

    # Tally & Decrypt
    agg_ciphertexts = server.tally_bids()
    tallies = trustee.decrypt_aggregate_tally(agg_ciphertexts)

    # Plaintext ladder is [100, 200, 300, 400, 500, 600, 700]
    # At 100: all 3 (tallies[0] == 3)
    # At 200: all 3 (tallies[1] == 3)
    # At 300: all 3 (tallies[2] == 3)
    # At 400: Charlie & Bob (tallies[3] == 2)
    # At 500: Bob only (tallies[4] == 1)
    # At 600, 700: 0
    assert tallies == (3, 3, 3, 2, 1, 0, 0)

    # First-price clearing: Bob wins at 500
    fp = determine_winner(ladder, tallies, pricing_rule="first_price")
    assert fp.clearing_price == 500
    assert fp.demand_at_clearing_price == 1
    assert fp.is_tie is False

    # Second-price clearing: Bob wins, pays 400 (second highest level)
    sp = determine_winner(ladder, tallies, pricing_rule="second_price")
    assert sp.clearing_price == 400
    assert sp.demand_at_clearing_price == 1


def test_auction_tie_detection(
    setup_auction_env: tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder],
) -> None:
    pub, priv, ladder = setup_auction_env
    server = AuctionServer(pub, ladder)
    trustee = Trustee(priv)

    # Both Alice and Bob bid 500
    b1 = Bidder("alice", pub, ladder).create_bid(500)
    b2 = Bidder("bob", pub, ladder).create_bid(500)
    server.submit_bid(b1)
    server.submit_bid(b2)

    tallies = trustee.decrypt_aggregate_tally(server.tally_bids())
    res = determine_winner(ladder, tallies, pricing_rule="first_price")
    assert res.clearing_price == 500
    assert res.demand_at_clearing_price == 2
    assert res.is_tie is True


def test_auction_zero_bids(
    setup_auction_env: tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder],
) -> None:
    pub, priv, ladder = setup_auction_env
    server = AuctionServer(pub, ladder)
    trustee = Trustee(priv)

    tallies = trustee.decrypt_aggregate_tally(server.tally_bids())
    res = determine_winner(ladder, tallies, pricing_rule="first_price")
    assert res.clearing_price is None
    assert res.demand_at_clearing_price == 0


def test_duplicate_bidder_id_rejected(
    setup_auction_env: tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder],
) -> None:
    pub, _, ladder = setup_auction_env
    server = AuctionServer(pub, ladder)
    b1 = Bidder("alice", pub, ladder).create_bid(300)
    b2 = Bidder("alice", pub, ladder).create_bid(400)

    server.submit_bid(b1)
    with pytest.raises(ValueError, match="Duplicate bidder ID rejected"):
        server.submit_bid(b2)


def test_out_of_range_bid_rejected(
    setup_auction_env: tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder],
) -> None:
    pub, _, ladder = setup_auction_env
    bidder = Bidder("david", pub, ladder)

    with pytest.raises(ValueError, match="outside price ladder range"):
        bidder.create_bid(50)  # Min is 100

    with pytest.raises(ValueError, match="outside price ladder range"):
        bidder.create_bid(9999)  # Max is 700


def test_malicious_vector_skew_attack(
    setup_auction_env: tuple[PaillierPublicKey, PaillierPrivateKey, PriceLadder],
) -> None:
    """Documenting the attack: Without ZK proofs, a malicious bidder skews the tally."""
    pub, priv, ladder = setup_auction_env
    server = AuctionServer(pub, ladder)
    trustee = Trustee(priv)

    # Honest bidder bids 200
    honest_bid = Bidder("honest", pub, ladder).create_bid(200)
    server.submit_bid(honest_bid)

    # Malicious bidder crafts an illegal vector with 999 at the highest level
    malicious_indicators = tuple(pub.encrypt(999) for _ in range(len(ladder)))
    malicious_bid = BidVector(
        bidder_id="attacker",
        encrypted_indicators=malicious_indicators,
    )
    server.submit_bid(malicious_bid)

    # Untrusted auctioneer tallies blindly
    tallies = trustee.decrypt_aggregate_tally(server.tally_bids())
    # Attacker's arbitrary 999 skews the tally, proving why production systems require ZK proofs
    assert tallies[-1] >= 999
