"""Key generation routines for the Paillier cryptosystem.

Educational reference implementation using pure Python arbitrary-precision integers.
"""

from __future__ import annotations

import math
import secrets

from week3_paillier_auction.crypto.math_utils import compute_lcm, is_probable_prime, mod_inverse


def generate_prime(bits: int) -> int:
    """Generate a random probable prime of exactly `bits` length.

    Args:
        bits: Bit length of the desired prime (minimum 16).

    Returns:
        A large probable prime integer.
    """
    if bits < 16:
        raise ValueError(f"Prime bit length must be at least 16, got {bits}")

    while True:
        # Generate random odd integer with MSB and LSB set
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, k=40):
            return candidate


def generate_keypair_components(key_size: int = 1024) -> dict[str, int]:
    """Generate Paillier keypair raw numerical components.

    Args:
        key_size: Total bit length of modulus n (e.g., 512, 1024, 2048).

    Returns:
        Dictionary with keys: 'n', 'g', 'n_squared', 'lambda_val', 'mu'.
    """
    if key_size < 64:
        raise ValueError(f"Key size must be at least 64 bits, got {key_size}")

    half_bits = key_size // 2

    # Generate two distinct primes p and q
    while True:
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        if p != q and math.gcd(p * q, (p - 1) * (q - 1)) == 1:
            break

    n = p * q
    n_squared = n * n
    lambda_val = compute_lcm(p - 1, q - 1)

    # Standard optimized generator: g = n + 1
    g = n + 1

    # For g = n + 1, L(g^lambda mod n^2) = lambda mod n, so mu = lambda^-1 mod n
    mu = mod_inverse(lambda_val, n)

    return {
        "n": n,
        "g": g,
        "n_squared": n_squared,
        "lambda_val": lambda_val,
        "mu": mu,
    }
