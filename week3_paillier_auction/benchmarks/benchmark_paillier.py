"""Benchmark suite evaluating Paillier key generation, encryption,
decryption, and homomorphic addition.

Educational reference implementation.
"""

from __future__ import annotations

import time

from week3_paillier_auction.crypto.paillier import generate_paillier_keypair


def benchmark_key_size(key_size: int, iterations: int = 10) -> dict[str, float]:
    """Measure average latency for keygen, encrypt, decrypt, and homomorphic add.

    Args:
        key_size: Paillier modulus bit length.
        iterations: Number of test iterations.

    Returns:
        Dictionary with timing metrics in milliseconds.
    """
    # Keygen benchmark
    t0 = time.perf_counter()
    pub, priv = generate_paillier_keypair(key_size=key_size)
    keygen_ms = (time.perf_counter() - t0) * 1000.0

    # Encryption benchmark
    enc_times: list[float] = []
    ciphertexts: list[int] = []
    for i in range(iterations):
        m = 100 + i
        t_start = time.perf_counter()
        c = pub.encrypt(m)
        enc_times.append((time.perf_counter() - t_start) * 1000.0)
        ciphertexts.append(c)

    # Decryption benchmark
    dec_times: list[float] = []
    for c in ciphertexts:
        t_start = time.perf_counter()
        _ = priv.decrypt(c)
        dec_times.append((time.perf_counter() - t_start) * 1000.0)

    # Homomorphic add benchmark
    add_times: list[float] = []
    for i in range(len(ciphertexts) - 1):
        t_start = time.perf_counter()
        _ = pub.homomorphic_add(ciphertexts[i], ciphertexts[i + 1])
        add_times.append((time.perf_counter() - t_start) * 1000.0)

    return {
        "key_size": float(key_size),
        "keygen_ms": keygen_ms,
        "encrypt_avg_ms": sum(enc_times) / len(enc_times),
        "decrypt_avg_ms": sum(dec_times) / len(dec_times),
        "homomorphic_add_avg_ms": sum(add_times) / len(add_times),
    }


def run_all_benchmarks() -> None:
    """Run benchmarks across 512, 1024, and 2048-bit keys."""
    print("=" * 80)
    print("PAILLIER CRYPTOSYSTEM BENCHMARK SUITE (PURE PYTHON)")
    print("=" * 80)
    header = (
        f"{'Key Size':<10} | {'Keygen (ms)':<14} | {'Encrypt (ms)':<14} | "
        f"{'Decrypt (ms)':<14} | {'Hom. Add (ms)':<14}"
    )
    print(header)
    print("-" * 80)

    for bits in [512, 1024]:
        res = benchmark_key_size(key_size=bits, iterations=5)
        row = (
            f"{int(res['key_size']):<10} | {res['keygen_ms']:<14.2f} | "
            f"{res['encrypt_avg_ms']:<14.2f} | {res['decrypt_avg_ms']:<14.2f} | "
            f"{res['homomorphic_add_avg_ms']:<14.4f}"
        )
        print(row)
    print("=" * 80)


if __name__ == "__main__":
    run_all_benchmarks()
