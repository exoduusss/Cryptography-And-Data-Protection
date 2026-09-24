# Week 3: Homomorphic Paillier Cryptosystem for Secure Sealed-Bid Auctions

## Overview

This module provides a pure-Python, zero-dependency implementation of the **Paillier partially homomorphic cryptosystem** (Pascal Paillier, EUROCRYPT 1999) and a multi-party **sealed-bid auction protocol** built on discrete price ladders.

Because partially homomorphic encryption supports addition ($E(m_1) \cdot E(m_2) \equiv E(m_1 + m_2)$) but cannot compare ciphertexts directly, the protocol solves the comparison barrier by encoding bids as **encrypted cumulative indicator vectors**.

> [!WARNING]
> This Paillier implementation is designed for **educational, cryptanalytic, and portfolio evaluation**. It uses pure Python arbitrary-precision integers and is **not constant-time** (vulnerable to timing side-channels). Production implementations require constant-time hardware-accelerated big-integer libraries.

---

## Mathematical Specification

- **Modulus**: $n = p \cdot q$, where $p, q$ are large independent primes generated via the Miller-Rabin test.
- **Carmichael Function**: $\lambda = \text{lcm}(p - 1, q - 1)$.
- **Generator**: $g = n + 1 \pmod{n^2}$, utilizing the binomial simplification $(1 + n)^m \equiv 1 + m \cdot n \pmod{n^2}$.
- **Decryption Multiplier**: $\mu = \lambda^{-1} \pmod n$.
- **L-Function**: $L(u) = \frac{u - 1}{n}$.
- **Homomorphic Addition**:
  $$E(m_1) \cdot E(m_2) \equiv g^{m_1 + m_2} (r_1 r_2)^n \pmod{n^2} \implies D(E(m_1) \cdot E(m_2)) = m_1 + m_2 \pmod n$$
- **Scalar Multiplication**:
  $$E(m)^k \equiv g^{k \cdot m} (r^k)^n \pmod{n^2} \implies D(E(m)^k) = k \cdot m \pmod n$$
- **Re-randomization**:
  $$E'(m) = E(m) \cdot r_{fresh}^n \pmod{n^2}$$

---

## Sealed-Bid Auction Architecture

1. **Bidders**: Encode bids over a discrete price ladder $[p_0, p_1, \dots, p_{K-1}]$ into cumulative indicator vectors $\mathbf{v} = [E(v_0), \dots, E(v_{K-1})]$ where $v_j = 1$ if $p_j \le \text{bid}$ else $0$.
2. **Untrusted Auctioneer (Public Key Only)**: Multiplies submitted vectors component-wise modulo $n^2$ to produce aggregate demand counts $\mathbf{C} = [C_0, \dots, C_{K-1}]$.
3. **Independent Trustee (Private Key Only)**: Decrypts **only the aggregate counts** $\mathbf{T} = [T_0, \dots, T_{K-1}]$. Individual bids are never decrypted.
4. **Winner Determination**:
   - **First-Price**: Highest price level with $T_j \ge 1$.
   - **Second-Price (Vickrey)**: Top bidder wins, but pays the second-highest bid level ($T_j \ge 2$).

---

## Interactive Demo & Benchmarks

### Run Interactive Sealed-Bid Auction Demo
Demonstrates Alice (₹500), Bob (₹750), and Charlie (₹650) with 2048-bit Paillier keys:
```powershell
python -m week3_paillier_auction.examples.auction_demo
```

### Run Key Size Benchmarks (512, 1024, 2048-bit)
```powershell
python -m week3_paillier_auction.benchmarks.benchmark_paillier
```

---

## Verification Gate

```powershell
ruff check week3_paillier_auction
ruff format --check week3_paillier_auction
mypy week3_paillier_auction
bandit -r week3_paillier_auction -x week3_paillier_auction/tests
pytest week3_paillier_auction --cov=week3_paillier_auction --cov-fail-under=85
```
