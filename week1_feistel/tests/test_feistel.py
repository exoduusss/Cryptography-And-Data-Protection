"""Unit tests for the core Feistel cipher engine."""

from __future__ import annotations

import secrets

import pytest

from week1_feistel.src.feistel import FeistelCipher
from week1_feistel.src.key_schedule import RotationalKeySchedule
from week1_feistel.src.round_function import ARXRoundFunction, SPNRoundFunction
from week1_feistel.src.substitution import CustomAffineSBox, FixedSBox, KeyDependentSBox


def test_feistel_block_roundtrip() -> None:
    key = secrets.token_bytes(16)
    cipher = FeistelCipher(key=key, rounds=16)
    block = b"ABCDEFGH"  # 8 bytes = 64 bits

    ct = cipher.encrypt_block(block)
    assert ct != block
    assert len(ct) == 8

    pt = cipher.decrypt_block(ct)
    assert pt == block


@pytest.mark.parametrize("rounds", [1, 2, 4, 8, 16, 32])
def test_feistel_varying_rounds(rounds: int) -> None:
    key = secrets.token_bytes(16)
    cipher = FeistelCipher(key=key, rounds=rounds)
    block = secrets.token_bytes(8)

    ct = cipher.encrypt_block(block)
    pt = cipher.decrypt_block(ct)
    assert pt == block


def test_feistel_pluggable_sboxes() -> None:
    key = secrets.token_bytes(16)
    block = b"12345678"

    # 1. Fixed S-Box
    c1 = FeistelCipher(key=key, round_function=SPNRoundFunction(sbox=FixedSBox()))
    ct1 = c1.encrypt_block(block)
    assert c1.decrypt_block(ct1) == block

    # 2. Key-dependent S-Box
    c2 = FeistelCipher(key=key, round_function=SPNRoundFunction(sbox=KeyDependentSBox(key)))
    ct2 = c2.encrypt_block(block)
    assert c2.decrypt_block(ct2) == block

    # 3. Custom S-Box
    c3 = FeistelCipher(key=key, round_function=SPNRoundFunction(sbox=CustomAffineSBox()))
    ct3 = c3.encrypt_block(block)
    assert c3.decrypt_block(ct3) == block

    # Different S-Boxes must produce different ciphertexts for the same input
    assert ct1 != ct2
    assert ct1 != ct3


def test_feistel_round_functions_and_schedules() -> None:
    key = secrets.token_bytes(16)
    block = b"TESTBLCK"

    # ARX round function
    c_arx = FeistelCipher(key=key, round_function=ARXRoundFunction())
    ct_arx = c_arx.encrypt_block(block)
    assert c_arx.decrypt_block(ct_arx) == block

    # Rotational key schedule
    c_rot = FeistelCipher(key=key, key_schedule=RotationalKeySchedule(key))
    ct_rot = c_rot.encrypt_block(block)
    assert c_rot.decrypt_block(ct_rot) == block


def test_modified_plaintext_changes_ciphertext() -> None:
    key = secrets.token_bytes(16)
    cipher = FeistelCipher(key=key, rounds=16)

    b1 = b"AAAAAAAB"
    b2 = b"AAAAAAAC"
    ct1 = cipher.encrypt_block(b1)
    ct2 = cipher.encrypt_block(b2)
    assert ct1 != ct2


def test_modified_key_changes_ciphertext() -> None:
    k1 = secrets.token_bytes(16)
    k2 = bytearray(k1)
    k2[0] ^= 0x01
    k2_bytes = bytes(k2)

    c1 = FeistelCipher(key=k1, rounds=16)
    c2 = FeistelCipher(key=k2_bytes, rounds=16)

    block = b"SECRET01"
    ct1 = c1.encrypt_block(block)
    ct2 = c2.encrypt_block(block)
    assert ct1 != ct2


def test_encrypt_block_with_rounds() -> None:
    key = secrets.token_bytes(16)
    cipher = FeistelCipher(key=key, rounds=8)
    block = b"ABCDEFGH"

    states = cipher.encrypt_block_with_rounds(block)
    assert len(states) == 9  # initial + 8 rounds
    assert states[0] == block
    assert states[-1] == cipher.encrypt_block(block)


def test_feistel_validation_errors() -> None:
    key = secrets.token_bytes(16)
    with pytest.raises(ValueError, match="Block size must be 8-byte"):
        FeistelCipher(key=key, block_size=16)

    with pytest.raises(ValueError, match="Master key must be at least 16 bytes"):
        FeistelCipher(key=b"short_key")

    with pytest.raises(ValueError, match="Rounds must be at least 1"):
        FeistelCipher(key=key, rounds=0)

    cipher = FeistelCipher(key=key)
    with pytest.raises(ValueError, match="Block length must be 8 bytes"):
        cipher.encrypt_block(b"short")
    with pytest.raises(ValueError, match="Block length must be 8 bytes"):
        cipher.decrypt_block(b"short")
    with pytest.raises(ValueError, match="Block length must be 8 bytes"):
        cipher.encrypt_block_with_rounds(b"short")
