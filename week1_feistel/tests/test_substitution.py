"""Unit tests for S-Box implementations and cryptanalytic analyzers."""

from __future__ import annotations

import secrets

import pytest

from week1_feistel.src.substitution import (
    CustomAffineSBox,
    FixedSBox,
    KeyDependentSBox,
    compute_differential_distribution_table,
    compute_nonlinearity,
    differential_uniformity,
    is_bijective,
)


def test_fixed_sbox_properties() -> None:
    sbox = FixedSBox()
    assert sbox.name == "fixed_rijndael"
    assert is_bijective(sbox.table) is True
    # Rijndael / AES S-Box has differential uniformity 4 and nonlinearity 112
    du = differential_uniformity(sbox.table)
    assert du == 4
    nl = compute_nonlinearity(sbox.table)
    assert nl == 112

    # Substitution lookup
    assert sbox.substitute(0x00) == 0x63
    assert sbox.substitute(0xFF) == 0x16


def test_key_dependent_sbox() -> None:
    key1 = secrets.token_bytes(16)
    key2 = secrets.token_bytes(16)
    sbox1 = KeyDependentSBox(key1)
    sbox2 = KeyDependentSBox(key2)

    assert sbox1.name == "key_dependent"
    assert is_bijective(sbox1.table) is True
    assert is_bijective(sbox2.table) is True
    # Different keys should produce different S-Boxes
    assert sbox1.table != sbox2.table

    with pytest.raises(ValueError, match="Master key must be at least 16 bytes"):
        KeyDependentSBox(b"too_short")


def test_custom_affine_sbox() -> None:
    sbox = CustomAffineSBox()
    assert sbox.name == "custom_hybrid"
    assert is_bijective(sbox.table) is True
    du = differential_uniformity(sbox.table)
    assert du > 0
    nl = compute_nonlinearity(sbox.table)
    assert nl > 0


def test_ddt_computation() -> None:
    sbox = FixedSBox()
    ddt = compute_differential_distribution_table(sbox.table)
    assert len(ddt) == 256
    assert len(ddt[0]) == 256
    # For dx = 0, dy = 0 must have count 256, all other dy must have count 0
    assert ddt[0][0] == 256
    assert sum(ddt[0]) == 256
    # Each row sum must equal 256
    for dx in range(256):
        assert sum(ddt[dx]) == 256


def test_invalid_fixed_sbox_size() -> None:
    with pytest.raises(ValueError, match="S-Box table must have 256 elements"):
        FixedSBox(table=[0] * 100)
