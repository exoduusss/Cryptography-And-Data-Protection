"""Mathematical utilities for Paillier cryptosystem: primality, modular arithmetic, and L-function.

Pure Python arbitrary-precision implementation. Educational reference implementation.
"""

from __future__ import annotations

import math
import secrets


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm.

    Returns:
        Tuple of (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> int:
    """Compute modular multiplicative inverse of a modulo m.

    Raises:
        ValueError: If a and m are not coprime.
    """
    if m <= 0:
        raise ValueError(f"Modulus must be positive, got {m}")
    try:
        return pow(a, -1, m)
    except ValueError as e:
        raise ValueError(f"{a} has no modular inverse modulo {m}") from e


def compute_lcm(a: int, b: int) -> int:
    """Compute Least Common Multiple of two integers."""
    return math.lcm(a, b)


def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test.

    Args:
        n: Integer candidate to test.
        k: Number of testing rounds (default 40 yields error probability < 2^-80).

    Returns:
        True if n is prime with high probability, False if composite.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Pre-test with small primes for rapid trial division
    small_primes = [
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
    ]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Factor out powers of 2 from n - 1: n - 1 = 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # uniform in [2, n - 2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue

        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False

    return True


def l_function(u: int, n: int) -> int:
    """Compute Paillier L-function: L(u) = (u - 1) // n.

    Args:
        u: Element congruent to 1 modulo n.
        n: Paillier modulus.

    Returns:
        Integer quotient (u - 1) // n.

    Raises:
        ValueError: If u is not congruent to 1 mod n.
    """
    if (u - 1) % n != 0:
        raise ValueError("L-function input u must be congruent to 1 mod n")
    return (u - 1) // n
