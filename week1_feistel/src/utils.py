"""Cryptographic utility functions for bitwise operations, padding, and metrics.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """Apply PKCS#7 padding to data for a given block size.

    Args:
        data: Raw plaintext bytes.
        block_size: Cipher block size in bytes (1 to 255). Default is 8 bytes (64 bits).

    Returns:
        Padded bytes with length as a multiple of block_size.

    Raises:
        ValueError: If block_size is outside the range [1, 255].
    """
    if block_size < 1 or block_size > 255:
        raise ValueError(f"Block size must be between 1 and 255 bytes, got {block_size}")
    remainder = len(data) % block_size
    pad_len = block_size - remainder
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    """Validate and strip PKCS#7 padding from padded data.

    Args:
        data: Padded ciphertext or plaintext bytes.
        block_size: Expected block size in bytes.

    Returns:
        Original unpadded bytes.

    Raises:
        ValueError: If input length is invalid, empty, or padding bytes are corrupted.
    """
    if not data:
        raise ValueError("Data cannot be empty for unpadding")
    if len(data) % block_size != 0:
        raise ValueError(
            f"Padded data length ({len(data)}) must be a multiple of block_size ({block_size})"
        )

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(f"Invalid PKCS#7 padding length: {pad_len}")

    # Constant-time comparison check on padding bytes to avoid timing leakage
    expected_pad = bytes([pad_len] * pad_len)
    actual_pad = data[-pad_len:]
    diff = 0
    for a, b in zip(expected_pad, actual_pad, strict=True):
        diff |= a ^ b

    if diff != 0:
        raise ValueError("Invalid PKCS#7 padding byte pattern")

    return data[:-pad_len]


def split_halves(block: bytes) -> tuple[int, int]:
    """Split a block into two big-endian integer halves (Left, Right).

    Args:
        block: Byte string of even length (e.g., 8 bytes for 64-bit block).

    Returns:
        Tuple of (left_int, right_int).

    Raises:
        ValueError: If block length is odd.
    """
    if len(block) % 2 != 0:
        raise ValueError(f"Block length must be even, got {len(block)}")
    half_len = len(block) // 2
    left = int.from_bytes(block[:half_len], byteorder="big")
    right = int.from_bytes(block[half_len:], byteorder="big")
    return left, right


def join_halves(left: int, right: int, half_size: int = 4) -> bytes:
    """Join two integer halves into a single big-endian byte string.

    Args:
        left: Left half integer.
        right: Right half integer.
        half_size: Size in bytes of each half (e.g., 4 bytes for 32 bits).

    Returns:
        Joined bytes of length 2 * half_size.
    """
    return left.to_bytes(half_size, byteorder="big") + right.to_bytes(half_size, byteorder="big")


def rot_left(val: int, bits: int, width: int = 32) -> int:
    """Perform circular left shift on an integer of given bit width."""
    bits = bits % width
    mask = (1 << width) - 1
    val &= mask
    return ((val << bits) & mask) | (val >> (width - bits))


def rot_right(val: int, bits: int, width: int = 32) -> int:
    """Perform circular right shift on an integer of given bit width."""
    bits = bits % width
    mask = (1 << width) - 1
    val &= mask
    return (val >> bits) | ((val << (width - bits)) & mask)


def hamming_weight(x: int) -> int:
    """Calculate the Hamming weight (number of 1s) of an integer."""
    return bin(x).count("1")


def hamming_distance(a: bytes, b: bytes) -> int:
    """Calculate the Hamming distance (number of differing bits) between two byte strings.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        Number of differing bit positions.

    Raises:
        ValueError: If byte strings have different lengths.
    """
    if len(a) != len(b):
        raise ValueError(f"Byte strings must have equal length ({len(a)} vs {len(b)})")
    return sum(hamming_weight(x ^ y) for x, y in zip(a, b, strict=True))
