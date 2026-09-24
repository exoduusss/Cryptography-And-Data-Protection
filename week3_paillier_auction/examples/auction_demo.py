"""Week 3 Interactive Demo: Sealed-Bid Homomorphic Auction.

Demonstrates:
Scenario:
  Bidder A (Alice) bids ₹500
  Bidder B (Bob) bids ₹750
  Bidder C (Charlie) bids ₹650
Price ladder: [100, 250, 500, 600, 650, 700, 750, 800, 900, 1000]

Pipeline:
  Step 1 [Plaintext]: Bidders construct cumulative demand vectors.
  Step 2 [Ciphertext]: Bidders encrypt vectors using Paillier public key.
  Step 3 [Homomorphic Tally]: Untrusted auctioneer multiplies ciphertexts mod n^2.
  Step 4 [Trustee Decryption]: Independent trustee decrypts ONLY the aggregate counts.
  Step 5 [Winner Determination]: Auctioneer identifies clearing price and winner.
"""

from __future__ import annotations

import time

from week3_paillier_auction.auction.auction_server import AuctionServer
from week3_paillier_auction.auction.bid import PriceLadder
from week3_paillier_auction.auction.bidder import Bidder
from week3_paillier_auction.auction.trustee import Trustee
from week3_paillier_auction.auction.winner_determination import determine_winner
from week3_paillier_auction.crypto.paillier import generate_paillier_keypair


def main() -> None:
    print("=" * 80)
    print("WEEK 3: HOMOMORPHIC PAILLIER SEALED-BID AUCTION DEMO")
    print("=" * 80)

    # 1. Setup Phase: Key generation and Price Ladder
    print("\n[SETUP PHASE]: Generating 2048-bit Paillier Keypair for Independent Trustee...")
    t0 = time.perf_counter()
    pub_key, priv_key = generate_paillier_keypair(key_size=2048)
    keygen_sec = time.perf_counter() - t0
    print(f"Trustee Keypair generated in {keygen_sec:.2f}s (Modulus n: {pub_key.bit_length} bits).")

    # Define discrete price ladder (in ₹ INR)
    price_ladder = PriceLadder([100, 250, 500, 600, 650, 700, 750, 800, 900, 1000])
    print(f"Discrete Price Ladder: {price_ladder.levels} (INR)")

    # Instantiate roles
    trustee = Trustee(private_key=priv_key)
    server = AuctionServer(public_key=pub_key, price_ladder=price_ladder)

    alice = Bidder("Alice", public_key=pub_key, price_ladder=price_ladder)
    bob = Bidder("Bob", public_key=pub_key, price_ladder=price_ladder)
    charlie = Bidder("Charlie", public_key=pub_key, price_ladder=price_ladder)

    # 2. Bidding Phase: Plaintext -> Ciphertext Vectors
    print("\n" + "-" * 80)
    print("STEP 1 & 2: BID ENCODING & ENCRYPTION")
    print("-" * 80)
    bids = [
        (alice, 500),
        (bob, 750),
        (charlie, 650),
    ]

    for bidder, amount in bids:
        # Step 1: Plaintext cumulative indicator vector
        plain_vector = [1 if level <= amount else 0 for level in price_ladder.levels]
        print(f"\n[PLAINTEXT] Bidder {bidder.bidder_id} submits bid of INR {amount}:")
        print(f"  Ladder: {list(price_ladder.levels)}")
        print(f"  Vector: {plain_vector}")

        # Step 2: Encrypted vector
        t_enc = time.perf_counter()
        bid_vec = bidder.create_bid(amount, cumulative=True)
        enc_ms = (time.perf_counter() - t_enc) * 1000.0
        server.submit_bid(bid_vec)

        ct0_hex = hex(bid_vec.encrypted_indicators[0])[:16]
        ct1_hex = hex(bid_vec.encrypted_indicators[-1])[:16]
        ct_preview = f"{ct0_hex}...{ct1_hex}..."
        print(f"  [CIPHERTEXT] Encrypted in {enc_ms:.1f}ms: {ct_preview}")

    # 3. Tallying Phase: Homomorphic Aggregation
    print("\n" + "-" * 80)
    print("STEP 3: HOMOMORPHIC TALLYING (UNTRUSTED AUCTIONEER)")
    print("-" * 80)
    print("Auctioneer computes component-wise product: C_j = Prod(E(v_i,j)) mod n^2")
    t_tally = time.perf_counter()
    aggregated_ciphertexts = server.tally_bids()
    tally_ms = (time.perf_counter() - t_tally) * 1000.0
    print(f"Homomorphic aggregation completed in {tally_ms:.2f}ms.")
    print(f"Aggregated Ciphertext Vector Count: {len(aggregated_ciphertexts)} levels.")
    print("Auctioneer CANNOT read the tallies because it lacks the private key.")

    # 4. Decryption Phase: Trustee Decrypts ONLY Aggregates
    print("\n" + "-" * 80)
    print("STEP 4: TRUSTEE DECRYPTION (AGGREGATE TALLY ONLY)")
    print("-" * 80)
    t_dec = time.perf_counter()
    decrypted_tallies = trustee.decrypt_aggregate_tally(aggregated_ciphertexts)
    dec_ms = (time.perf_counter() - t_dec) * 1000.0
    print(f"Trustee decrypted {len(decrypted_tallies)} aggregate levels in {dec_ms:.1f}ms.")
    print(f"[POST-DECRYPTION] Demand Count Per Level: {list(decrypted_tallies)}")

    # 5. Winner Determination
    print("\n" + "-" * 80)
    print("STEP 5: WINNER DETERMINATION")
    print("-" * 80)

    # First-Price Auction
    fp_res = determine_winner(price_ladder, decrypted_tallies, pricing_rule="first_price")
    print("\n[First-Price Auction Result]:")
    print(f"  Winning Clearing Price: INR {fp_res.clearing_price}")
    print(f"  Demand at Clearing Price: {fp_res.demand_at_clearing_price}")
    print(f"  Tie Detected: {fp_res.is_tie}")
    print(f"  Outcome: Bob wins at INR {fp_res.clearing_price}!")

    # Second-Price (Vickrey) Auction
    sp_res = determine_winner(price_ladder, decrypted_tallies, pricing_rule="second_price")
    print("\n[Second-Price (Vickrey) Auction Result]:")
    top_lvl = (
        price_ladder[sp_res.winning_level_index]
        if sp_res.winning_level_index is not None
        else "N/A"
    )
    print(f"  Top Bid Level: INR {top_lvl}")
    print(f"  Second-Price Clearing Price: INR {sp_res.clearing_price}")
    print(f"  Outcome: Bob wins, paying the second-highest bid level: INR {sp_res.clearing_price}!")

    # 6. Privacy & Secrecy Summary
    print("\n" + "=" * 80)
    print("CONFIDENTIALITY AUDIT:")
    print("1. Alice's bid (INR 500) and Charlie's bid (INR 650) were NEVER decrypted.")
    print("2. The Trustee never saw individual bidder vectors.")
    print("3. The Auctioneer never held the private key.")
    print("=" * 80)
    print("WEEK 3 DEMO COMPLETE: Homomorphic auction protocol successfully executed.")
    print("=" * 80)


if __name__ == "__main__":
    main()
