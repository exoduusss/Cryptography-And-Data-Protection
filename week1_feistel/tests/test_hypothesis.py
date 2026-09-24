"""Property-based fuzzing tests using Hypothesis for the Feistel cipher and modes."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from week1_feistel.src.feistel import FeistelCipher
from week1_feistel.src.modes import CBCMode, CTRMode, ECBMode


@settings(deadline=None, max_examples=30)
@given(
    key=st.binary(min_size=16, max_size=16),
    block=st.binary(min_size=8, max_size=8),
    rounds=st.integers(min_value=1, max_value=8),
)
def test_hypothesis_feistel_block_inversion(key: bytes, block: bytes, rounds: int) -> None:
    cipher = FeistelCipher(key=key, rounds=rounds)
    ct = cipher.encrypt_block(block)
    pt = cipher.decrypt_block(ct)
    assert pt == block


@settings(deadline=None, max_examples=25)
@given(
    key=st.binary(min_size=16, max_size=16),
    plaintext=st.binary(min_size=0, max_size=128),
)
def test_hypothesis_cbc_mode_inversion(key: bytes, plaintext: bytes) -> None:
    cipher = FeistelCipher(key=key, rounds=6)
    cbc = CBCMode(cipher)
    ct = cbc.encrypt(plaintext)
    pt = cbc.decrypt(ct)
    assert pt == plaintext


@settings(deadline=None, max_examples=25)
@given(
    key=st.binary(min_size=16, max_size=16),
    plaintext=st.binary(min_size=0, max_size=128),
)
def test_hypothesis_ctr_mode_inversion(key: bytes, plaintext: bytes) -> None:
    cipher = FeistelCipher(key=key, rounds=6)
    ctr = CTRMode(cipher)
    ct = ctr.encrypt(plaintext)
    pt = ctr.decrypt(ct)
    assert pt == plaintext


@settings(deadline=None, max_examples=25)
@given(
    key=st.binary(min_size=16, max_size=16),
    plaintext=st.binary(min_size=0, max_size=128),
)
def test_hypothesis_ecb_mode_inversion(key: bytes, plaintext: bytes) -> None:
    cipher = FeistelCipher(key=key, rounds=6)
    ecb = ECBMode(cipher)
    ct = ecb.encrypt(plaintext)
    pt = ecb.decrypt(ct)
    assert pt == plaintext
