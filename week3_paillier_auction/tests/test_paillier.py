"""Unit tests for pure Python Paillier cryptosystem operations."""

from __future__ import annotations

import pytest

from week3_paillier_auction.crypto.paillier import (
    PaillierPrivateKey,
    PaillierPublicKey,
    generate_paillier_keypair,
)


@pytest.fixture(scope="session")
def paillier_512() -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Session-scoped 512-bit keypair for fast testing."""
    return generate_paillier_keypair(key_size=512)


def test_encrypt_decrypt_roundtrip(
    paillier_512: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_512
    messages = [0, 1, 42, 255, 123456789]
    for m in messages:
        c = pub.encrypt(m)
        dec = priv.decrypt(c)
        assert dec == m


def test_homomorphic_addition(
    paillier_512: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_512
    m1 = 150
    m2 = 275

    c1 = pub.encrypt(m1)
    c2 = pub.encrypt(m2)
    c_sum = pub.homomorphic_add(c1, c2)

    dec_sum = priv.decrypt(c_sum)
    assert dec_sum == m1 + m2


def test_homomorphic_scalar_multiplication(
    paillier_512: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_512
    m = 25
    k = 7

    c = pub.encrypt(m)
    c_prod = pub.scalar_multiply(c, k)

    dec_prod = priv.decrypt(c_prod)
    assert dec_prod == m * k


def test_re_randomization(
    paillier_512: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_512
    m = 99
    c1 = pub.encrypt(m)
    c2 = pub.re_randomize(c1)

    # Re-randomized ciphertext is distinct from original
    assert c1 != c2
    # Both decrypt to the same plaintext
    assert priv.decrypt(c1) == m
    assert priv.decrypt(c2) == m


def test_plaintext_range_validation(
    paillier_512: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, _ = paillier_512
    with pytest.raises(ValueError, match="out of range"):
        pub.encrypt(-1)
    with pytest.raises(ValueError, match="out of range"):
        pub.encrypt(pub.n + 10)


def test_ciphertext_range_validation(
    paillier_512: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_512
    with pytest.raises(ValueError, match="out of valid range"):
        priv.decrypt(0)
    with pytest.raises(ValueError, match="out of valid range"):
        priv.decrypt(pub.n * pub.n + 5)
