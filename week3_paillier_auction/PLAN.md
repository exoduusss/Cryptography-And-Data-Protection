# Week 3 Implementation Plan: Homomorphic Paillier Cryptosystem for Secure Sealed-Bid Auctions

## Overview
Implement the Paillier partially homomorphic cryptosystem from scratch in pure Python using arbitrary-precision integers (`pow(base, exp, mod)`), and build a privacy-preserving sealed-bid auction protocol that solves the comparison limitation of homomorphic encryption using discrete price ladder tallying.

---

## Day-by-Day Checklist & Work Stages

### Day 1: Mathematical Foundations & Research
- [x] Study Pascal Paillier's 1999 paper *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*.
- [x] Specify mathematical primitives: Miller-Rabin primality testing with `secrets`, Carmichael function $\lambda(n) = \text{lcm}(p-1, q-1)$, generator $g = n + 1$, $L(u) = (u - 1) // n$, and modular inverse.
- [x] Document homomorphic properties:
  - Additive: $D(E(m_1) \cdot E(m_2) \pmod{n^2}) = m_1 + m_2 \pmod n$
  - Scalar multiplication: $D(E(m_1)^k \pmod{n^2}) = k \cdot m_1 \pmod n$
  - Re-randomization: $E'(m) = E(m) \cdot r^n \pmod{n^2}$
- **Expected Commit**: `docs(w3-paillier): document Paillier mathematics and homomorphic auction protocol`

### Day 2: Architecture & Protocol Design Docs
- [x] Write `docs/mathematics.md`: Mathematical proofs, Decisional Composite Residuosity Assumption (DCRA), and overflow boundaries.
- [x] Write `docs/architecture.md`: Multi-party sequence diagrams for Bidders, Untrusted Auctioneer, and Independent Trustee.
- [x] Write `docs/protocol.md`: Step-by-step vector tallying protocol (cumulative price ladders, aggregate tally, tie resolution, first/second-price clearing).
- [x] Write `docs/security_analysis.md`: Non-collusion assumptions, malicious bidder vectors (why ZK proofs are necessary in production), metadata leakage.
- **Expected Commit**: `docs(w3-paillier): add architecture, protocol specifications, and security analysis`

### Day 3: Pure-Python Paillier Cryptographic Core
- [x] `crypto/math_utils.py`: GCD, Extended Euclidean Algorithm / modular inverse, LCM, Miller-Rabin probabilistic primality test, $L(u) = (u - 1) // n$.
- [x] `crypto/key_generation.py`: Prime generation with `secrets.randbits`, safe candidate testing, keypair generation $(n, g)$ and $(\lambda, \mu)$.
- [x] `crypto/paillier.py`: `PaillierPublicKey`, `PaillierPrivateKey`, `encrypt`, `decrypt`, `homomorphic_add`, `scalar_multiply`, `re_randomize`, plaintext range validation.
- **Expected Commit**: `feat(w3-paillier): implement pure Python Paillier cryptosystem from scratch`

### Day 4: Multi-Party Sealed-Bid Auction Engine
- [x] `auction/bid.py`: Price ladder definitions, BidVector representation (one-hot and cumulative indicators).
- [x] `auction/bidder.py`: Bidder client encrypting price ladder vectors with public key.
- [x] `auction/auction_server.py`: Untrusted auctioneer tallying ciphertexts homomorphically ($\prod C_i \pmod{n^2}$) without holding private keys.
- [x] `auction/trustee.py`: Isolated trustee holding private key, decrypting only aggregated price-level counts.
- [x] `auction/winner_determination.py`: Computes clearing price (first-price or second-price / Vickrey) and identifies winning bidder IDs.
- **Expected Commit**: `feat(w3-paillier): implement sealed-bid auction with homomorphic tallying`

### Day 5: Benchmarking, CLI & Interactive Demo
- [x] `benchmarks/benchmark_paillier.py`: Benchmarks keygen, encrypt, decrypt, and homomorphic add across 512, 1024, and 2048-bit keys.
- [x] `examples/auction_demo.py`: Interactive auction scenario (Alice ₹500, Bob ₹750, Charlie ₹650), displaying each stage: Plaintext -> Ciphertext Vector -> Homomorphic Tally -> Trustee Decryption -> Winner Result.
- **Expected Commit**: `feat(w3-paillier): add key size benchmarks and interactive auction demonstration`

### Day 6: Comprehensive Testing Suite
- [x] `tests/test_math.py`: Miller-Rabin, modular inverse, LCM, and corner cases.
- [x] `tests/test_paillier.py`: Keygen, encrypt/decrypt roundtrips, homomorphic addition, scalar multiplication, re-randomization, plaintext overflow.
- [x] `tests/test_hypothesis_paillier.py`: Property-based testing with 512-bit cached keypairs.
- [x] `tests/test_auction.py`: Full auction runs, ties, zero bids, duplicate bidder IDs, out-of-ladder bids, invalid vector attack demonstration.
- **Expected Commit**: `test(w3-paillier): add unit, property-based, and auction protocol tests`

### Day 7: Final Documentation, Verification Gate & Tag
- [x] Write `week3_paillier_auction/README.md`.
- [x] Write repository root `README.md` including 3-week roadmap, tech stack, installation, testing commands, Mermaid diagrams, security summary, and references.
- [x] Run Verification Gate (ruff, mypy, bandit, pytest >=85%, demo).
- [x] Merge `feat/w3-paillier-auction` into `develop`.
- [x] Merge `develop` into `main` and tag `v0.3.0-week3`.
- [x] Run FINAL GATE & fresh-clone validation check in temporary folder.
- **Expected Commit**: `chore(w3-paillier): finalize week 3, complete root documentation, and verify release`

---

## Definition of Done
1. Zero external C-extension dependencies (pure Python integers).
2. 100% pass on all verification gate commands.
3. Code coverage strictly $\ge 85\%$.
4. All auction test scenarios (including ties, duplicate rejection, and out-of-range bids) pass.
5. Local Git tag `v0.3.0-week3` verified.
