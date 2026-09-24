"""Tests for Week 1 CLI entry point."""

from __future__ import annotations

import io

import pytest

from week1_feistel.src.cli import main


def test_cli_encrypt_decrypt_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    key_hex = "000102030405060708090a0b0c0d0e0f"
    plaintext = "Secure Test Message"

    # Encrypt
    out_capture = io.StringIO()
    monkeypatch.setattr("sys.stdout", out_capture)
    ret_enc = main(
        [
            "encrypt",
            "--key",
            key_hex,
            "--data",
            plaintext,
            "--mode",
            "cbc",
            "--rounds",
            "8",
            "--sbox",
            "fixed",
        ]
    )
    assert ret_enc == 0
    ct_hex = out_capture.getvalue().strip()
    assert len(ct_hex) > 0

    # Decrypt
    out_capture_dec = io.StringIO()
    monkeypatch.setattr("sys.stdout", out_capture_dec)
    ret_dec = main(
        [
            "decrypt",
            "--key",
            key_hex,
            "--data-hex",
            ct_hex,
            "--mode",
            "cbc",
            "--rounds",
            "8",
            "--sbox",
            "fixed",
        ]
    )
    assert ret_dec == 0
    dec_out = out_capture_dec.getvalue().strip()
    assert f"Decrypted text: {plaintext}" in dec_out


def test_cli_analyze_command(monkeypatch: pytest.MonkeyPatch) -> None:
    out_capture = io.StringIO()
    monkeypatch.setattr("sys.stdout", out_capture)
    ret = main(["analyze", "--sbox", "fixed"])
    assert ret == 0
    out = out_capture.getvalue()
    assert "S-Box Analysis: fixed_rijndael" in out
    assert "Bijective:                True" in out
    assert "Differential Uniformity:  4" in out
    assert "Walsh Nonlinearity:       112" in out


def test_cli_error_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    err_capture = io.StringIO()
    monkeypatch.setattr("sys.stderr", err_capture)

    # Invalid hex key
    ret = main(["encrypt", "--key", "not_valid_hex", "--data", "hello"])
    assert ret == 1

    # Missing data flag
    ret2 = main(["encrypt", "--key", "00" * 16])
    assert ret2 == 1
