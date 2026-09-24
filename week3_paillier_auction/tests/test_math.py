"""Unit tests for mathematical utilities in the Paillier cryptosystem."""

from __future__ import annotations

import pytest

from week3_paillier_auction.crypto.math_utils import (
    compute_lcm,
    extended_gcd,
    is_probable_prime,
    l_function,
    mod_inverse,
)


def test_extended_gcd() -> None:
    g, x, y = extended_gcd(30, 50)
    assert g == 10
    assert 30 * x + 50 * y == 10


def test_mod_inverse() -> None:
    inv = mod_inverse(3, 11)
    assert (3 * inv) % 11 == 1

    with pytest.raises(ValueError, match="no modular inverse"):
        mod_inverse(6, 9)

    with pytest.raises(ValueError, match="Modulus must be positive"):
        mod_inverse(3, 0)


def test_lcm() -> None:
    assert compute_lcm(4, 6) == 12
    assert compute_lcm(12, 18) == 36


def test_is_probable_prime() -> None:
    known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 101, 103, 107, 109, 65537]
    for p in known_primes:
        assert is_probable_prime(p) is True

    composites = [-10, 0, 1, 4, 6, 8, 9, 15, 21, 25, 27, 33, 100, 105, 65535]
    for c in composites:
        assert is_probable_prime(c) is False


def test_l_function() -> None:
    n = 101
    # u = 1 + 5 * n = 506
    u = 1 + 5 * n
    assert l_function(u, n) == 5

    with pytest.raises(ValueError, match="congruent to 1 mod n"):
        l_function(100, n)
