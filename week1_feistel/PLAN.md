# Week 1 Implementation Plan: Feistel Block Cipher with Custom S-Boxes

## Overview
Develop a configurable, modular Feistel block cipher supporting customizable block sizes (default: 64-bit / 8 bytes), key sizes (default: 128-bit / 16 bytes), and round counts (default: 16). The architecture features a clean separation between the generic Feistel permutation, deterministic key schedule, pluggable round substitution functions, block cipher modes (ECB, CBC, CTR), and cryptanalytic assessment tools.

---

## Day-by-Day Checklist & Work Stages

### Day 1: Research & Requirements
- [x] Study Feistel structural principles (Horst Feistel 1973), Luby-Rackoff theorem (4 rounds for pseudo-random permutation).
- [x] Specify interface contracts for Feistel cipher, round functions, key schedules, and cipher modes.
- [x] Document mathematical criteria for S-box security: bijectivity, differential uniformity, Walsh-Hadamard nonlinearity, Strict Avalanche Criterion (SAC).
- **Expected Commit**: `docs(w1-feistel): specify cryptographic requirements and mathematical foundations`

### Day 2: Architecture & Design Docs
- [x] Write `docs/architecture.md` with Mermaid diagram depicting the Feistel network, round function structure, and key schedule.
- [x] Write `docs/theory.md` explaining confusion & diffusion (Shannon 1949), round reversal for decryption, and mode semantics.
- [x] Write `docs/security_analysis.md` outlining chosen-plaintext attacks, slide attacks, mode vulnerabilities, and timing limitations.
- **Expected Commit**: `docs(w1-feistel): add architecture, theory, and security analysis documentation`

### Day 3: Implementation of Core Primitives
- [x] `week1_feistel/src/utils.py`: Bitwise conversions, byte packing/unpacking, circular rotations, PKCS#7 padding & unpadding with timing considerations and strict validation.
- [x] `week1_feistel/src/substitution.py`: S-box generation and implementations:
  1. Fixed S-box (AES-derived / Rijndael affine map on $\mathbb{F}_{2^8}$).
  2. Key-dependent S-box (Fisher-Yates shuffle parameterized by HKDF/KDF expanded key material).
  3. Custom affine-power hybrid S-box ($S(x) = (x^7 \oplus 0x63) \pmod{256}$ with bijection repair).
  - Cryptanalysis metrics: Bijectivity verification, Difference Distribution Table (DDT) & differential uniformity, Walsh-Hadamard transform & nonlinearity calculation.
- [x] `week1_feistel/src/permutation.py`: P-box bitwise and nibble permutations for linear diffusion.
- [x] `week1_feistel/src/key_schedule.py`: Deterministic round-key derivation using HKDF-SHA256 and linear feedback round expansion.
- [x] `week1_feistel/src/round_function.py`: Pluggable round functions integrating substitution, expansion/compression, and permutation.
- [x] `week1_feistel/src/feistel.py`: Core `FeistelCipher` class executing generic round logic $L_{i+1} = R_i$, $R_{i+1} = L_i \oplus F(R_i, K_i)$ for encryption and exact symmetric reversed keys for decryption.
- **Expected Commit**: `feat(w1-feistel): implement core feistel engine, key schedule, and pluggable s-boxes`

### Day 4: Block Cipher Modes & Padding
- [x] `week1_feistel/src/modes.py`:
  - `ECBMode`: Electronic Codebook (with warning regarding semantic insecurity for patterns).
  - `CBCMode`: Cipher Block Chaining with randomized IV, XOR chaining, and PKCS#7 padding validation.
  - `CTRMode`: Counter mode transforming block cipher into a stream cipher with nonces and big-endian counters.
- **Expected Commit**: `feat(w1-feistel): implement ECB, CBC, and CTR block cipher modes`

### Day 5: Cryptanalysis Engine, CLI & Demo
- [x] `week1_feistel/src/cli.py`: Command-line interface with `encrypt`, `decrypt`, and `analyze` subcommands.
- [x] `week1_feistel/examples/demo.py`: End-to-end interactive demonstration running encryption/decryption roundtrips, tampering detection, and avalanche test with visualization.
- [x] Avalanche experiment: Generate diffusion curve plotting round number vs. average flipped output bits, saving to `docs/images/week1_avalanche.png`.
- **Expected Commit**: `feat(w1-feistel): add cryptanalysis engine, CLI, and avalanche visualization demo`

### Day 6: Comprehensive Testing & Security Hardening
- [x] `week1_feistel/tests/test_feistel.py`: Core engine round-trip tests, invertible property under all round functions.
- [x] `week1_feistel/tests/test_modes.py`: Known-answer vectors, PKCS#7 padding corruption, IV tampering tests.
- [x] `week1_feistel/tests/test_sbox.py`: Bijectivity, differential uniformity, and nonlinearity mathematical properties.
- [x] `week1_feistel/tests/test_hypothesis.py`: Property-based fuzzing testing arbitrary plaintexts and keys across all modes.
- **Expected Commit**: `test(w1-feistel): add comprehensive unit, property-based, and security tests`

### Day 7: Documentation, Verification Gate & Release Tag
- [x] Write `week1_feistel/README.md`.
- [x] Run Verification Gate:
  1. `ruff check .`
  2. `ruff format --check .`
  3. `mypy week1_feistel`
  4. `bandit -r week1_feistel -x week1_feistel/tests`
  5. `pytest week1_feistel --cov=week1_feistel --cov-fail-under=85`
  6. `python -m week1_feistel.examples.demo`
- [x] Merge `feat/w1-feistel-core` into `develop`.
- [x] Merge `develop` into `main` and create tag `v0.1.0-week1`.
- **Expected Commit**: `chore(w1-feistel): finalize week 1 documentation, gate validation, and release`

---

## Definition of Done
1. All files typed, documented, and adhering to workspace rules.
2. 100% pass on all verification gate commands.
3. Code coverage strictly $\ge 85\%$.
4. Matplotlib runs headless (`Agg`) and generates `docs/images/week1_avalanche.png`.
5. Local Git tag `v0.1.0-week1` verified.
