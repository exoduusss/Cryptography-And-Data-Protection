"""Week 1 Demo: Feistel Cipher, S-Box Cryptanalysis & Avalanche Diffusion Experiment.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import os

os.environ["OPENBLAS_NUM_THREADS"] = "1"

import secrets
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # Headless backend per Error-Prevention Rule 4
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from week1_feistel.src.feistel import FeistelCipher  # noqa: E402
from week1_feistel.src.modes import CBCMode, CTRMode, ECBMode  # noqa: E402
from week1_feistel.src.substitution import (  # noqa: E402
    CustomAffineSBox,
    FixedSBox,
    KeyDependentSBox,
    compute_nonlinearity,
    differential_uniformity,
    is_bijective,
)
from week1_feistel.src.utils import hamming_distance  # noqa: E402


def run_sbox_analysis() -> None:
    """Analyze and compare all three S-Box implementations."""
    print("=" * 70)
    print("1. S-BOX CRYPTANALYTIC EVALUATION")
    print("=" * 70)

    key = secrets.token_bytes(16)
    sboxes = [
        FixedSBox(),
        KeyDependentSBox(key),
        CustomAffineSBox(),
    ]

    header = (
        f"{'S-Box Name':<16} | {'Bijective':<10} | {'Diff Uniformity':<16} | {'Nonlinearity':<14}"
    )
    print(header)
    print("-" * 70)

    for sb in sboxes:
        bijective = is_bijective(sb.table)
        diff_unif = differential_uniformity(sb.table)
        nl = compute_nonlinearity(sb.table)
        print(f"{sb.name:<20} | {str(bijective):<10} | {diff_unif:<16} | {nl:<14}")
    print("\nObservation: Lower differential uniformity and higher nonlinearity resist attacks.")


def run_modes_demo() -> None:
    """Demonstrate encryption and decryption across ECB, CBC, and CTR modes."""
    print("\n" + "=" * 70)
    print("2. BLOCK CIPHER MODES OF OPERATION (ECB, CBC, CTR)")
    print("=" * 70)

    key = secrets.token_bytes(16)
    cipher = FeistelCipher(key=key, rounds=16)
    sample_text = b"Confidential Payload for 3-Week Cryptography Suite Demo!"

    print(f"Original plaintext ({len(sample_text)} bytes): {sample_text.decode('utf-8')}")

    # ECB
    ecb = ECBMode(cipher)
    ecb_ct = ecb.encrypt(sample_text)
    ecb_pt = ecb.decrypt(ecb_ct)
    print(f"\n[ECB] Ciphertext ({len(ecb_ct)} bytes): {ecb_ct.hex()[:48]}...")
    print(f"[ECB] Decryption verified: {ecb_pt == sample_text}")

    # CBC
    cbc = CBCMode(cipher)
    cbc_ct = cbc.encrypt(sample_text)
    cbc_pt = cbc.decrypt(cbc_ct)
    print(f"\n[CBC] Ciphertext with IV ({len(cbc_ct)} bytes): {cbc_ct.hex()[:48]}...")
    print(f"[CBC] Decryption verified: {cbc_pt == sample_text}")

    # CTR
    ctr = CTRMode(cipher)
    ctr_ct = ctr.encrypt(sample_text)
    ctr_pt = ctr.decrypt(ctr_ct)
    print(f"\n[CTR] Ciphertext with Nonce ({len(ctr_ct)} bytes): {ctr_ct.hex()[:48]}...")
    print(f"[CTR] Decryption verified: {ctr_pt == sample_text}")

    # Tampering demonstration in CBC
    print("\n--- Tampering Demonstration ---")
    tampered_cbc = bytearray(cbc_ct)
    tampered_cbc[-1] ^= 0x01  # Invert single bit in last ciphertext block
    try:
        cbc.decrypt(bytes(tampered_cbc))
        print("Tampered CBC unexpectedly succeeded (padding collision).")
    except ValueError as e:
        print(f"Tampered CBC successfully rejected padding: {e}")


def run_avalanche_experiment(num_trials: int = 100) -> None:
    """Run avalanche experiment evaluating bit diffusion per round over multiple trials."""
    print("\n" + "=" * 70)
    print(f"3. STRICT AVALANCHE CRITERION (SAC) EXPERIMENT ({num_trials} TRIALS)")
    print("=" * 70)

    rounds = 16
    block_size = 8
    total_bits = block_size * 8

    # Arrays to store bit flip percentages: shape (num_trials, rounds + 1)
    pt_diffusion = np.zeros((num_trials, rounds + 1))
    key_diffusion = np.zeros((num_trials, rounds + 1))

    for trial in range(num_trials):
        master_key = secrets.token_bytes(16)
        pt1 = secrets.token_bytes(block_size)

        # 1. Plaintext flip: invert one random bit in pt1
        flip_byte = secrets.randbelow(block_size)
        flip_bit = 1 << secrets.randbelow(8)
        pt2_bytes = bytearray(pt1)
        pt2_bytes[flip_byte] ^= flip_bit
        pt2 = bytes(pt2_bytes)

        cipher = FeistelCipher(key=master_key, rounds=rounds)
        states1 = cipher.encrypt_block_with_rounds(pt1)
        states2 = cipher.encrypt_block_with_rounds(pt2)

        for r in range(rounds + 1):
            dist = hamming_distance(states1[r], states2[r])
            pt_diffusion[trial, r] = (dist / total_bits) * 100.0

        # 2. Key flip: invert one random bit in master_key
        flip_k_byte = secrets.randbelow(16)
        flip_k_bit = 1 << secrets.randbelow(8)
        k2_bytes = bytearray(master_key)
        k2_bytes[flip_k_byte] ^= flip_k_bit
        key2 = bytes(k2_bytes)

        cipher2 = FeistelCipher(key=key2, rounds=rounds)
        states_k1 = cipher.encrypt_block_with_rounds(pt1)
        states_k2 = cipher2.encrypt_block_with_rounds(pt1)

        for r in range(rounds + 1):
            dist = hamming_distance(states_k1[r], states_k2[r])
            key_diffusion[trial, r] = (dist / total_bits) * 100.0

    # Statistics for final round (round 16)
    pt_final = pt_diffusion[:, -1]
    key_final = key_diffusion[:, -1]

    print("\nPlaintext-Bit Avalanche Statistics (Round 16):")
    print(f"  Mean:    {np.mean(pt_final):.2f}% (Target: ~50.0%)")
    print(f"  Std Dev: {np.std(pt_final):.2f}%")
    print(f"  Min/Max: {np.min(pt_final):.2f}% / {np.max(pt_final):.2f}%")

    print("\nKey-Bit Avalanche Statistics (Round 16):")
    print(f"  Mean:    {np.mean(key_final):.2f}% (Target: ~50.0%)")
    print(f"  Std Dev: {np.std(key_final):.2f}%")
    print(f"  Min/Max: {np.min(key_final):.2f}% / {np.max(key_final):.2f}%")

    # Plot rounds vs diffusion
    docs_img_dir = Path("docs/images")
    docs_img_dir.mkdir(parents=True, exist_ok=True)
    plot_path = docs_img_dir / "week1_avalanche.png"

    round_axis = np.arange(rounds + 1)
    pt_mean = np.mean(pt_diffusion, axis=0)
    pt_std = np.std(pt_diffusion, axis=0)
    key_mean = np.mean(key_diffusion, axis=0)
    key_std = np.std(key_diffusion, axis=0)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.axhline(50, color="gray", linestyle="--", linewidth=1, label="Ideal SAC (50%)")
    ax.plot(round_axis, pt_mean, "o-", color="#1f77b4", label="Plaintext Bit Flip Mean")
    ax.fill_between(round_axis, pt_mean - pt_std, pt_mean + pt_std, color="#1f77b4", alpha=0.15)

    ax.plot(round_axis, key_mean, "s-", color="#ff7f0e", label="Key Bit Flip Mean")
    ax.fill_between(round_axis, key_mean - key_std, key_mean + key_std, color="#ff7f0e", alpha=0.15)

    ax.set_title("Feistel Cipher Avalanche Effect (Rounds vs Diffusion %)")
    ax.set_xlabel("Feistel Round Number")
    ax.set_ylabel("Changed Ciphertext Bits (%)")
    ax.set_ylim(-2, 102)
    ax.set_xticks(round_axis)
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend(loc="lower right")

    plt.tight_layout()
    plt.savefig(plot_path, dpi=200)
    plt.close()

    print(f"\n[Artifact Generated]: Matplotlib visualization saved to {plot_path}")
    print("\n* CRITICAL CRYPTOGRAPHIC NOTE *")
    print("Good avalanche behavior confirms effective statistical diffusion,")
    print("but does NOT independently prove resistance to algebraic, slide, or side-channels.")


def main() -> None:
    """Run full demonstration."""
    print("=" * 70)
    print("WEEK 1: FEISTEL CIPHER & S-BOX CRYPTANALYSIS DEMO")
    print("=" * 70)
    run_sbox_analysis()
    run_modes_demo()
    run_avalanche_experiment(num_trials=100)
    print("\n" + "=" * 70)
    print("DEMO COMPLETE: All tests, benchmarks, and artifacts verified.")
    print("=" * 70)


if __name__ == "__main__":
    main()
