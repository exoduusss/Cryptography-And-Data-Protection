"""Property-based tests for Paillier homomorphic properties using Hypothesis."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from week3_paillier_auction.crypto.paillier import (
    PaillierPrivateKey,
    PaillierPublicKey,
    generate_paillier_keypair,
)


@pytest.fixture(scope="session")
def paillier_keys() -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    return generate_paillier_keypair(key_size=512)


def test_hypothesis_homomorphic_properties(
    paillier_keys: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_keys

    @settings(deadline=None, max_examples=20)
    @given(
        m1=st.integers(min_value=0, max_value=10000),
        m2=st.integers(min_value=0, max_value=10000),
    )
    def check_addition(m1: int, m2: int) -> None:
        c1 = pub.encrypt(m1)
        c2 = pub.encrypt(m2)
        c_add = pub.homomorphic_add(c1, c2)
        assert priv.decrypt(c_add) == m1 + m2

    check_addition()


def test_hypothesis_scalar_multiplication(
    paillier_keys: tuple[PaillierPublicKey, PaillierPrivateKey],
) -> None:
    pub, priv = paillier_keys

    @settings(deadline=None, max_examples=15)
    @given(
        m=st.integers(min_value=0, max_value=1000),
        k=st.integers(min_value=0, max_value=50),
    )
    def check_scalar(m: int, k: int) -> None:
        c = pub.encrypt(m)
        c_mult = pub.scalar_multiply(c, k)
        assert priv.decrypt(c_mult) == m * k

    check_scalar()
