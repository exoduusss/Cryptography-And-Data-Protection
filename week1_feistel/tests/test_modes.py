"""Unit tests for block cipher operational modes (ECB, CBC, CTR)."""

from __future__ import annotations

import secrets

import pytest

from week1_feistel.src.feistel import FeistelCipher
from week1_feistel.src.modes import CBCMode, CTRMode, ECBMode


@pytest.fixture
def cipher() -> FeistelCipher:
    key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    return FeistelCipher(key=key, rounds=16)


def test_ecb_roundtrip(cipher: FeistelCipher) -> None:
    ecb = ECBMode(cipher)
    for length in [0, 1, 7, 8, 9, 15, 16, 17, 64, 100]:
        data = secrets.token_bytes(length)
        ct = ecb.encrypt(data)
        assert len(ct) % 8 == 0
        pt = ecb.decrypt(ct)
        assert pt == data


def test_ecb_pattern_leakage(cipher: FeistelCipher) -> None:
    ecb = ECBMode(cipher)
    # Identical 8-byte blocks must encrypt to identical ciphertext blocks
    pt = b"AAAAAAAABBBBBBBBAAAAAAAA"
    ct = ecb.encrypt(pt)
    c0 = ct[0:8]
    c1 = ct[8:16]
    c2 = ct[16:24]
    assert c0 == c2
    assert c0 != c1


def test_cbc_roundtrip(cipher: FeistelCipher) -> None:
    cbc = CBCMode(cipher)
    for length in [0, 1, 5, 8, 12, 16, 25, 70]:
        data = secrets.token_bytes(length)
        ct = cbc.encrypt(data)
        assert len(ct) >= 16  # IV (8) + at least 1 block (8)
        assert len(ct) % 8 == 0
        pt = cbc.decrypt(ct)
        assert pt == data


def test_cbc_explicit_iv(cipher: FeistelCipher) -> None:
    cbc = CBCMode(cipher)
    iv = b"\xaa" * 8
    data = b"Predictable IV test data"
    ct1 = cbc.encrypt(data, iv=iv)
    ct2 = cbc.encrypt(data, iv=iv)
    assert ct1 == ct2

    with pytest.raises(ValueError, match="IV must be exactly 8 bytes"):
        cbc.encrypt(data, iv=b"short")


def test_cbc_tamper_detection(cipher: FeistelCipher) -> None:
    cbc = CBCMode(cipher)
    data = b"Sensitive Financial Transaction Record"
    ct = bytearray(cbc.encrypt(data))

    # Invert bit in the last byte
    ct[-1] ^= 0x01
    try:
        dec = cbc.decrypt(bytes(ct))
        # If by rare chance unpad didn't fail, plaintext must not match
        assert dec != data
    except ValueError as e:
        assert "padding" in str(e)


def test_ctr_roundtrip(cipher: FeistelCipher) -> None:
    ctr = CTRMode(cipher)
    for length in [0, 1, 3, 8, 15, 33, 99]:
        data = secrets.token_bytes(length)
        ct = ctr.encrypt(data)
        # In CTR mode, length of ciphertext = 4 bytes (nonce) + len(plaintext)
        assert len(ct) == 4 + len(data)
        pt = ctr.decrypt(ct)
        assert pt == data


def test_ctr_tamper_isolation(cipher: FeistelCipher) -> None:
    ctr = CTRMode(cipher)
    data = b"Hello, World! 12345678"
    ct = bytearray(ctr.encrypt(data))

    # Tamper with 5th byte of payload (index 4 + 4 = 8)
    ct[8] ^= 0x20
    pt = ctr.decrypt(bytes(ct))
    # In CTR, bit flips in ciphertext directly affect only the corresponding plaintext bit
    assert pt != data
    assert pt[0:4] == data[0:4]
    assert pt[4] == data[4] ^ 0x20
    assert pt[5:] == data[5:]


def test_modes_error_handling(cipher: FeistelCipher) -> None:
    ecb = ECBMode(cipher)
    with pytest.raises(ValueError, match="Ciphertext length must be a non-zero multiple"):
        ecb.decrypt(b"")
    with pytest.raises(ValueError, match="Ciphertext length must be a non-zero multiple"):
        ecb.decrypt(b"123")

    cbc = CBCMode(cipher)
    with pytest.raises(ValueError, match="Ciphertext too short for CBC"):
        cbc.decrypt(b"1234567")
    with pytest.raises(ValueError, match="Ciphertext length must be a multiple"):
        cbc.decrypt(b"A" * 17)

    ctr = CTRMode(cipher)
    with pytest.raises(ValueError, match="Nonce must be exactly 4 bytes"):
        ctr.encrypt(b"data", nonce=b"12")
    with pytest.raises(ValueError, match="Ciphertext too short for CTR mode"):
        ctr.decrypt(b"12")
