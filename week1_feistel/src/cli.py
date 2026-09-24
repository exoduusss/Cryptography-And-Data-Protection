"""Command Line Interface for Week 1 Feistel Cipher.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import argparse
import sys

from week1_feistel.src.feistel import FeistelCipher
from week1_feistel.src.modes import BaseMode, CBCMode, CTRMode, ECBMode
from week1_feistel.src.round_function import SPNRoundFunction
from week1_feistel.src.substitution import (
    BaseSBox,
    CustomAffineSBox,
    FixedSBox,
    KeyDependentSBox,
    compute_nonlinearity,
    differential_uniformity,
    is_bijective,
)


def get_sbox(name: str, key: bytes) -> BaseSBox:
    """Instantiate S-box by name."""
    clean_name = name.lower().strip()
    if clean_name in ("fixed", "rijndael"):
        return FixedSBox()
    elif clean_name in ("key_dependent", "key-dependent"):
        return KeyDependentSBox(key)
    elif clean_name in ("custom", "hybrid", "affine"):
        return CustomAffineSBox()
    else:
        raise ValueError(
            f"Unknown S-Box '{name}'. Valid choices: 'fixed', 'key_dependent', 'custom'"
        )


def build_cipher(key: bytes, rounds: int, sbox_name: str) -> FeistelCipher:
    """Build FeistelCipher instance with selected parameters."""
    sbox = get_sbox(sbox_name, key)
    round_fn = SPNRoundFunction(sbox=sbox)
    return FeistelCipher(key=key, rounds=rounds, round_function=round_fn)


def main(argv: list[str] | None = None) -> int:
    """Entry point for Feistel CLI."""
    parser = argparse.ArgumentParser(description="Feistel Block Cipher CLI (Educational Reference)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt parser
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt plaintext")
    enc_parser.add_argument("--rounds", type=int, default=16, help="Number of rounds (default: 16)")
    enc_parser.add_argument(
        "--sbox",
        type=str,
        default="fixed",
        choices=["fixed", "key_dependent", "custom"],
        help="S-box implementation",
    )
    enc_parser.add_argument(
        "--mode",
        type=str,
        default="cbc",
        choices=["ecb", "cbc", "ctr"],
        help="Block cipher mode",
    )
    enc_parser.add_argument("--key", type=str, required=True, help="128-bit key as hex string")
    enc_parser.add_argument("--data", type=str, help="Plaintext UTF-8 string to encrypt")
    enc_parser.add_argument("--data-hex", type=str, help="Plaintext hex string")

    # Decrypt parser
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt ciphertext")
    dec_parser.add_argument("--rounds", type=int, default=16, help="Number of rounds (default: 16)")
    dec_parser.add_argument(
        "--sbox",
        type=str,
        default="fixed",
        choices=["fixed", "key_dependent", "custom"],
        help="S-box implementation",
    )
    dec_parser.add_argument(
        "--mode",
        type=str,
        default="cbc",
        choices=["ecb", "cbc", "ctr"],
        help="Block cipher mode",
    )
    dec_parser.add_argument("--key", type=str, required=True, help="128-bit key as hex string")
    dec_parser.add_argument(
        "--data-hex", type=str, required=True, help="Ciphertext hex string to decrypt"
    )

    # Analyze parser
    ana_parser = subparsers.add_parser("analyze", help="Analyze S-Box cryptanalytic properties")
    ana_parser.add_argument(
        "--sbox",
        type=str,
        default="fixed",
        choices=["fixed", "key_dependent", "custom"],
        help="S-box to analyze",
    )
    ana_parser.add_argument(
        "--key",
        type=str,
        default="000102030405060708090a0b0c0d0e0f",
        help="Master key for key_dependent sbox",
    )

    args = parser.parse_args(argv)

    try:
        key_bytes = bytes.fromhex(args.key)
    except Exception as e:
        sys.stderr.write(f"Error parsing hex key: {e}\n")
        return 1

    if args.command == "encrypt":
        if args.data is not None:
            plain_bytes = args.data.encode("utf-8")
        elif args.data_hex is not None:
            plain_bytes = bytes.fromhex(args.data_hex)
        else:
            sys.stderr.write("Must specify either --data or --data-hex\n")
            return 1

        cipher = build_cipher(key_bytes, args.rounds, args.sbox)
        mode_runner: BaseMode
        if args.mode == "ecb":
            mode_runner = ECBMode(cipher)
        elif args.mode == "cbc":
            mode_runner = CBCMode(cipher)
        else:
            mode_runner = CTRMode(cipher)
        ct = mode_runner.encrypt(plain_bytes)

        print(ct.hex())
        return 0

    elif args.command == "decrypt":
        ct_bytes = bytes.fromhex(args.data_hex)
        cipher = build_cipher(key_bytes, args.rounds, args.sbox)
        mode_runner_dec: BaseMode
        if args.mode == "ecb":
            mode_runner_dec = ECBMode(cipher)
        elif args.mode == "cbc":
            mode_runner_dec = CBCMode(cipher)
        else:
            mode_runner_dec = CTRMode(cipher)
        pt = mode_runner_dec.decrypt(ct_bytes)

        try:
            print(f"Decrypted text: {pt.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"Decrypted hex: {pt.hex()}")
        return 0

    elif args.command == "analyze":
        sbox = get_sbox(args.sbox, key_bytes)
        bijective = is_bijective(sbox.table)
        diff_unif = differential_uniformity(sbox.table)
        nonlinearity = compute_nonlinearity(sbox.table)

        print(f"--- S-Box Analysis: {sbox.name} ---")
        print(f"Bijective:                {bijective}")
        print(f"Differential Uniformity:  {diff_unif} (lower is better; AES is 4)")
        print(f"Walsh Nonlinearity:       {nonlinearity} (higher is better; AES is 112)")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
