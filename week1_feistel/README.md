# Week 1: Feistel Block Cipher with Custom S-Boxes

## Overview

This module provides a modular, configurable implementation of a **Feistel block cipher** written from cryptographic first principles in Python 3.11+. The design cleanly isolates the core symmetric network structure, deterministic round-key scheduling, pluggable byte substitution boxes (S-boxes), diffusion bit permutations (P-boxes), and operational block cipher modes (ECB, CBC, CTR) with PKCS#7 padding.

> [!WARNING]
> This cipher is implemented for **educational, cryptanalytic, and portfolio evaluation purposes**. It is **not** hardened against side-channel analysis and must not be used to encrypt sensitive production data.

---

## Architectural Features

- **Configurable Parameters**:
  - Block size: 64 bits (8 bytes), split into two 32-bit integer halves ($L, R$).
  - Master key: 128 bits (16 bytes) default.
  - Round count: 16 rounds default (customizable from 1 to 32+).
- **Core Feistel Invertibility**:
  $$L_{i+1} = R_i$$
  $$R_{i+1} = L_i \oplus F(R_i, K_i)$$
  Decryption executes the identical symmetric logic with reversed round subkeys $(K_{r-1}, \dots, K_0)$.
- **Pluggable Substitution Boxes (S-Boxes)**:
  1. `FixedSBox`: Derived from Rijndael / AES $\mathbb{F}_{2^8}$ inversion with affine transformation ($\delta = 4, NL = 112$).
  2. `KeyDependentSBox`: Dynamically generated per master key via Fisher-Yates shuffle seeded with HKDF-SHA256 output.
  3. `CustomAffineSBox`: Custom documented algebraic design: $x \mapsto (x^7 \oplus 0x63) \pmod{256}$ with bijective collision resolution.
- **Key Scheduling**:
  - `HKDFKeySchedule`: RFC 5869 extract-and-expand key derivation utilizing HMAC-SHA256.
  - `RotationalKeySchedule`: Round-constant based golden-ratio rotation key expander.
- **Modes of Operation**:
  - `ECBMode`: Electronic Codebook with PKCS#7 padding (illustrates pattern leakage).
  - `CBCMode`: Cipher Block Chaining with randomized IVs and PKCS#7 padding validation.
  - `CTRMode`: Counter mode transforming the block cipher into a streaming keystream generator.

---

## Cryptanalytic Metrics & Avalanche Experiment

The suite includes quantitative tools to evaluate S-Box resilience:
- **Bijectivity**: Confirms that $S$ is a bijective permutation on $\{0, \dots, 255\}$.
- **Differential Uniformity ($\delta$)**: Computes the Difference Distribution Table (DDT) and finds $\max_{\Delta x \neq 0, \Delta y} \text{DDT}[\Delta x][\Delta y]$.
- **Nonlinearity ($NL$)**: Fast Walsh-Hadamard Transform (FWHT) computing distance to affine functions.
- **Strict Avalanche Criterion (SAC)**: Evaluates the diffusion rate across 16 rounds for both plaintext and key single-bit perturbations. Generates diffusion plots saved to `docs/images/week1_avalanche.png`.

---

## CLI & Demo Execution

### CLI Encryption / Decryption
```powershell
# Encrypt UTF-8 text using CBC mode with 16 rounds and fixed S-Box
python -m week1_feistel.src.cli encrypt --key 000102030405060708090a0b0c0d0e0f --data "Confidential Payload" --mode cbc --rounds 16 --sbox fixed

# Decrypt ciphertext hex string
python -m week1_feistel.src.cli decrypt --key 000102030405060708090a0b0c0d0e0f --data-hex <CIPHERTEXT_HEX> --mode cbc --rounds 16 --sbox fixed

# Analyze S-Box cryptanalytic properties
python -m week1_feistel.src.cli analyze --sbox fixed
```

### Interactive Demo & Diffusion Visualization
```powershell
python -m week1_feistel.examples.demo
```
This script executes S-box comparisons, mode demonstrations, and generates the avalanche diffusion curve at `docs/images/week1_avalanche.png`.

---

## Testing & Quality Gate

```powershell
ruff check week1_feistel
ruff format --check week1_feistel
mypy week1_feistel
bandit -r week1_feistel -x week1_feistel/tests
pytest week1_feistel --cov=week1_feistel --cov-fail-under=85
```
