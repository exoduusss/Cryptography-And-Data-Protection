"""Unit tests for cryptographic utility functions."""

from __future__ import annotations

import pytest

from week1_feistel.src.utils import (
    hamming_distance,
    hamming_weight,
    join_halves,
    pkcs7_pad,
    pkcs7_unpad,
    rot_left,
    rot_right,
    split_halves,
)


def test_pkcs7_pad_unpad_roundtrip() -> None:
    for length in range(32):
        data = b"A" * length
        padded = pkcs7_pad(data, block_size=8)
        assert len(padded) % 8 == 0
        assert len(padded) > len(data)
        unpadded = pkcs7_unpad(padded, block_size=8)
        assert unpadded == data


def test_pkcs7_invalid_block_size() -> None:
    with pytest.raises(ValueError, match="Block size must be between"):
        pkcs7_pad(b"data", block_size=0)
    with pytest.raises(ValueError, match="Block size must be between"):
        pkcs7_pad(b"data", block_size=256)


def test_pkcs7_unpad_corrupt() -> None:
    with pytest.raises(ValueError, match="Data cannot be empty"):
        pkcs7_unpad(b"", block_size=8)

    with pytest.raises(ValueError, match="must be a multiple of block_size"):
        pkcs7_unpad(b"1234567", block_size=8)

    # Invalid padding length byte (e.g. 0 or > block_size)
    with pytest.raises(ValueError, match="Invalid PKCS#7 padding length"):
        pkcs7_unpad(b"\x00" * 8, block_size=8)
    with pytest.raises(ValueError, match="Invalid PKCS#7 padding length"):
        pkcs7_unpad(b"1234567\x09", block_size=8)

    # Inconsistent padding bytes
    corrupt_pad = b"1234\x04\x04\x03\x04"
    with pytest.raises(ValueError, match="Invalid PKCS#7 padding byte pattern"):
        pkcs7_unpad(corrupt_pad, block_size=8)


def test_split_and_join_halves() -> None:
    block = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    left, right = split_halves(block)
    assert left == 0x01020304
    assert right == 0x05060708
    joined = join_halves(left, right, half_size=4)
    assert joined == block

    with pytest.raises(ValueError, match="Block length must be even"):
        split_halves(b"\x01\x02\x03")


def test_rotations() -> None:
    val = 0x80000001
    assert rot_left(val, 1, 32) == 0x00000003
    assert rot_right(val, 1, 32) == 0xC0000000
    assert rot_left(val, 32, 32) == val
    assert rot_right(val, 32, 32) == val


def test_hamming_metrics() -> None:
    assert hamming_weight(0) == 0
    assert hamming_weight(0xFF) == 8
    assert hamming_weight(0x0F) == 4

    assert hamming_distance(b"\x00\x00", b"\x00\x01") == 1
    assert hamming_distance(b"\xff\x00", b"\x00\xff") == 16

    with pytest.raises(ValueError, match="Byte strings must have equal length"):
        hamming_distance(b"\x01", b"\x01\x02")
