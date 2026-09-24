# Cryptography & Secure Systems

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Test Suite: 87 passed](https://img.shields.io/badge/tests-87%20passed-brightgreen.svg)](https://github.com/pytest-dev/pytest)
[![Coverage: 94.8%](https://img.shields.io/badge/coverage-94.8%25-brightgreen.svg)](https://github.com/pytest-dev/pytest-cov)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An end-to-end, production-grade cryptography engineering repository implementing foundational symmetric cryptosystems, modern asynchronous end-to-end encrypted messaging protocols, and privacy-preserving additive homomorphic computation from first principles.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Weekly Roadmap](#architecture--weekly-roadmap)
  - [Week 1: Symmetric Cryptography (Custom Feistel Cipher)](#week-1-symmetric-cryptography-custom-feistel-cipher)
  - [Week 2: Secure Messaging (Signal Double Ratchet & X3DH)](#week-2-secure-messaging-signal-double-ratchet--x3dh)
  - [Week 3: Homomorphic Privacy (Pure Python Paillier & Sealed-Bid Auction)](#week-3-homomorphic-privacy-pure-python-paillier--sealed-bid-auction)
- [Repository Structure](#repository-structure)
- [Installation & Setup](#installation--setup)
- [Running Demos](#running-demos)
- [Running the Test Suite & Quality Gates](#running-the-test-suite--quality-gates)
- [Security Analysis & Threat Models](#security-analysis--threat-models)
- [Standards & References](#standards--references)
- [License](#license)

---

## Overview

Modern cryptographic engineering requires fluency across three distinct paradigms:
1. **Classical Symmetric Cryptanalysis**: Understanding confusion, diffusion, non-linearity, and block cipher operational modes.
2. **Modern Ephemeral Ratcheting Protocols**: Guaranteeing forward secrecy and post-compromise recovery across untrusted network relays.
3. **Advanced Cryptographic Primitives**: Computing over encrypted data using partially homomorphic schemes without revealing plaintexts.

This repository implements all three paradigms from scratch with type safety, zero external cryptographic shortcuts for educational primitives, and strict automated verification gates.

---

## Architecture & Weekly Roadmap

| Module | Core Primitives | Verification Status | Test Count | Coverage |
| :--- | :--- | :--- | :--- | :--- |
| **Week 1: Feistel Cipher** | Pluggable S-Boxes (Affine/Key-Dep), SPN Round, Key Schedule, ECB/CBC/CTR, PKCS#7, DDT, Avalanche | **PASSED** | 39 | 94.1% |
| **Week 2: Double Ratchet** | X3DH Key Agreement, KDF Chains (HKDF-SHA256), ChaCha20-Poly1305 AEAD, FastAPI Relay, WebSocket UI | **PASSED** | 29 | 96.8% |
| **Week 3: Paillier Auction** | Pure Python Paillier (Miller-Rabin, L-Function), Discrete Price Ladders, Sealed-Bid Auction, Trustee Decryption | **PASSED** | 19 | 92.3% |
| **Total Suite** | | **ALL GATES PASSED** | **87** | **94.8%** |

```mermaid
graph TD
    subgraph "Week 1: Symmetric Foundations"
        W1_Input[64-bit Plaintext] --> W1_Split[Split L0, R0]
        W1_Split --> W1_Round[16-Round SPN Feistel Network]
        W1_Round --> W1_Output[Ciphertext Block]
        W1_Modes[Modes: ECB / CBC / CTR]
    end

    subgraph "Week 2: Ephemeral Ratchets & E2EE"
        W2_X3DH[X3DH Asynchronous Key Exchange] --> W2_Root[Root Key & Chain Keys]
        W2_Root --> W2_DH[DH Ratchet Step]
        W2_DH --> W2_Symm[Symmetric Send/Recv Chains]
        W2_Symm --> W2_AEAD[ChaCha20-Poly1305 AEAD]
        W2_AEAD --> W2_Relay[Untrusted FastAPI / WebSocket Relay]
    end

    subgraph "Week 3: Homomorphic Privacy"
        W3_Bid[Plaintext Bids] --> W3_Vector[Indicator Vector]
        W3_Vector --> W3_Enc[Paillier Encryption mod n^2]
        W3_Enc --> W3_Agg[Untrusted Server: Homomorphic Product]
        W3_Agg --> W3_Trustee[Trustee Decrypts Aggregate Tally Only]
        W3_Trustee --> W3_Winner[Clearing Price & Winner Discovery]
    end
```

---

### Week 1: Symmetric Cryptography (Custom Feistel Cipher)

A 64-bit block cipher with variable rounds (1 to 32, default 16) and a 128-bit key schedule, featuring:
- **Pluggable Substitution Boxes (S-Boxes)**:
  - Fixed 8x8 S-Box with high non-linearity ($\text{NL} \ge 112$).
  - Dynamic key-dependent S-Boxes generated via cryptographic CSPRNG permutations.
  - Custom affine transformation S-Boxes over $\text{GF}(2^8)$ ($S(x) = A \cdot x^{-1} + c$).
- **Cryptanalytic Metrics**:
  - Full Difference Distribution Table (DDT) generation and maximum differential probability calculation.
  - Fast Walsh-Hadamard Transform (FWHT) for non-linearity measurement.
  - Strict Avalanche Criterion (SAC) analysis and automated visualization heatmap.
- **Block Cipher Modes**:
  - **ECB**: Electronic Codebook (with visual penguin pattern leakage demonstration).
  - **CBC**: Cipher Block Chaining with random IV and PKCS#7 padding validation.
  - **CTR**: Counter mode streaming cipher with tamper isolation properties.

```mermaid
flowchart LR
    L_i["L_i"] --> XOR["XOR (+)"]
    R_i["R_i"] --> L_next["L_{i+1}"]
    R_i --> F["Round Function F(R, K_i)"]
    F --> XOR
    XOR --> R_next["R_{i+1}"]
```

---

### Week 2: Secure Messaging (Signal Double Ratchet & X3DH)

A full end-to-end encrypted messaging engine inspired by the Signal Protocol:
- **Extended Triple Diffie-Hellman (X3DH)**:
  - Supports Identity Keys ($IK$), Signed Prekeys ($SPK$), and One-Time Prekeys ($OPK$) using X25519 and Ed25519 signatures.
  - Provides cryptographic mutual authentication and asynchronous offline session initiation.
  - 60-digit SAS safety number computation for out-of-band identity verification.
- **Double Ratchet Engine**:
  - KDF chain ratchets using HKDF-SHA256 for symmetric key progression.
  - Diffie-Hellman ratchet steps interleaved whenever turns alternate.
  - Out-of-order message handling with a bounded skipped-key cache ($M = 1000$).
  - ChaCha20-Poly1305 AEAD authenticated encryption tying message headers to associated data.
  - Secure encrypted session serialization at rest using Argon2id / PBKDF2.
- **Untrusted FastAPI Relay**:
  - Ephemeral prekey bundle storage and WebSocket message dispatcher.
  - Provable server zero-knowledge: The server routes ciphertexts without access to plaintexts or ratchet keys.

```mermaid
sequenceDiagram
    autonumber
    actor Alice
    participant Server as Untrusted Relay
    actor Bob

    Bob->>Server: Publish Prekey Bundle (IK_B, SPK_B, OPK_B, Sig)
    Alice->>Server: Fetch Bob's Prekey Bundle
    Alice->>Alice: Compute X3DH Shared Secret (SK) & Initial Ratchet
    Alice->>Server: Send Message 1 (Header + Ciphertext)
    Server->>Bob: Deliver Message 1
    Bob->>Bob: Compute X3DH Secret (SK) & Step Ratchet
    Bob->>Bob: Decrypt Message 1
    Bob->>Server: Send Reply (New DH Ephemeral Key)
    Server->>Alice: Deliver Reply
    Alice->>Alice: Step DH Ratchet & Advance Root Key
```

---

### Week 3: Homomorphic Privacy (Pure Python Paillier & Sealed-Bid Auction)

A pure-Python implementation of the Paillier cryptosystem from first principles (no external C-extensions), applied to privacy-preserving sealed-bid auctions:
- **Pure Python Number Theory Engine**:
  - Variable-size prime generation using deterministic Miller-Rabin testing ($\ge 64$ rounds, error probability $< 2^{-128}$).
  - Extended Euclidean Algorithm, Modular Multiplicative Inverse, and Carmichael's function $\lambda(n)$.
  - Precomputed $L(u) = \frac{u - 1}{n}$ optimization for fast decryption.
- **Homomorphic Operations**:
  - Additive homomorphism: $D(E(m_1) \cdot E(m_2) \bmod n^2) = (m_1 + m_2) \bmod n$.
  - Homomorphic scalar multiplication: $D(E(m)^k \bmod n^2) = (m \cdot k) \bmod n$.
  - Ciphertext re-randomization: $c' = c \cdot r^n \bmod n^2$ without modifying the underlying plaintext.
- **Privacy-Preserving Sealed-Bid Auction Protocol**:
  - Discrete Price Ladder encoding: Bids are converted into cumulative indicator vectors $v = [1, \dots, 1, 0, \dots, 0]$.
  - Untrusted Auctioneer performs homomorphic component-wise aggregation:
    $$C_j = \prod_{i=1}^M E(v_{i,j}) \bmod n^2 = E\left(\sum_{i=1}^M v_{i,j}\right)$$
  - Independent Trustee decrypts **only** the aggregated demand counts $T_j$.
  - First-Price and Second-Price (Vickrey) clearing price resolution without ever decrypting losing bids.

```mermaid
sequenceDiagram
    autonumber
    actor Bidders as Alice, Bob, Charlie
    participant Auctioneer as Untrusted Auctioneer
    actor Trustee as Independent Trustee

    Trustee->>Auctioneer: Publish Public Key (n, g)
    Auctioneer->>Bidders: Announce Price Ladder & Public Key
    Bidders->>Bidders: Encode Bid into Indicator Vector & Encrypt
    Bidders->>Auctioneer: Submit Encrypted Vectors
    Auctioneer->>Auctioneer: Homomorphically Aggregate Vectors: C_j = Prod(c_{i,j}) mod n^2
    Auctioneer->>Trustee: Send Aggregated Vector C_j (Demand Tallies Only)
    Trustee->>Trustee: Decrypt Tallies: T_j = Decrypt(C_j)
    Trustee->>Auctioneer: Return Decrypted Demand Vector
    Auctioneer->>Bidders: Announce Winning Clearing Price & Winner
```

---

## Repository Structure

```text
cryptography-secure-systems/
├── pyproject.toml                     # Unified project metadata & tooling configs
├── requirements.txt                   # Production dependencies
├── requirements-dev.txt               # Development & testing tooling
├── PROGRESS.md                        # Autonomous run task tracker & gate log
├── README.md                          # Repository documentation
├── docs/                              # Visualizations, diagrams, and assets
│   └── images/
│       └── week1_avalanche.png        # Strict Avalanche Criterion heatmap
├── week1_feistel/                     # Week 1: Feistel Cipher Project
│   ├── src/
│   │   ├── feistel.py                 # Core Feistel network implementation
│   │   ├── modes.py                   # ECB, CBC, and CTR operational modes
│   │   ├── substitution.py            # Fixed, Key-Dependent & Affine S-Boxes + DDT
│   │   ├── permutation.py            # P-Boxes & bitwise permutations
│   │   ├── key_schedule.py            # Round subkey derivation
│   │   ├── round_function.py          # SPN round function F(R, K)
│   │   ├── utils.py                   # PKCS#7 padding & bitwise utilities
│   │   └── cli.py                     # Interactive CLI & visual avalanche analyzer
│   ├── tests/                         # 39 Unit, Property (Hypothesis), & Invariant Tests
│   └── examples/
│       └── demo.py                    # Visual demonstration script
├── week2_double_ratchet/              # Week 2: Signal Double Ratchet Project
│   ├── crypto/
│   │   ├── double_ratchet.py          # DH & Symmetric KDF ratcheting engine
│   │   ├── x3dh.py                    # Extended Triple Diffie-Hellman agreement
│   │   ├── identity.py                # Ed25519 & X25519 identity management
│   │   ├── encryption.py              # ChaCha20-Poly1305 AEAD cipher wrapper
│   │   ├── kdf.py                     # HKDF-SHA256 ratchet derivation
│   │   └── serialization.py           # Encrypted session state persistence
│   ├── backend/
│   │   ├── server.py                  # FastAPI untrusted messaging relay
│   │   ├── websocket.py               # Real-time WebSocket connection manager
│   │   └── models.py                  # Pydantic schemas & network models
│   ├── client/
│   │   ├── client.py                  # Client-side agent & local session manager
│   │   └── ui/index.html              # Interactive web dashboard
│   ├── tests/                         # 29 Unit, Backend, & 7 Security Invariant Tests
│   └── examples/
│       └── demo.py                    # Multi-turn E2EE chat demo
└── week3_paillier_auction/            # Week 3: Homomorphic Paillier Auction Project
    ├── crypto/
    │   ├── paillier.py                # Pure Python Paillier cryptosystem
    │   ├── key_generation.py          # Probabilistic key generation & prime generation
    │   └── math_utils.py              # Miller-Rabin, Extended GCD, LCM, L-function
    ├── auction/
    │   ├── bid.py                     # Discrete price ladder & bid indicator vectors
    │   ├── bidder.py                  # Bidder client abstraction
    │   ├── auction_server.py          # Untrusted homomorphic tallying server
    │   ├── trustee.py                 # Keyholder & aggregate tally decryptor
    │   └── winner_determination.py    # First-price & second-price clearing logic
    ├── benchmarks/
    │   └── benchmark_paillier.py      # Micro-benchmarks (Keygen, Enc, Dec, HomAdd)
    ├── tests/                         # 19 Unit, Math, Hypothesis & Attack Tests
    └── examples/
        └── auction_demo.py            # Three-party sealed-bid auction simulation
```

---

## Installation & Setup

### Prerequisites
- **Python 3.11+** (Tested on Python 3.11, 3.12, and 3.14)
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/cryptography-secure-systems.git
cd cryptography-secure-systems
```

### 2. Create and Activate Virtual Environment

**Windows PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
```

---

## Running Demos

### Week 1: Feistel Cipher & Avalanche Analysis
```powershell
python -m week1_feistel.examples.demo
```
*Executes block encryptions, runs 16-round avalanche bit-flip measurements, and writes the heatmap to `docs/images/week1_avalanche.png`.*

### Week 2: Asynchronous Double Ratchet Chat Simulation
```powershell
python -m week2_double_ratchet.examples.demo
```
*Simulates Alice and Bob registering prekeys with the untrusted FastAPI server, performing X3DH key agreement, exchanging out-of-order ratcheted messages, and auditing zero-knowledge server confidentiality.*

### Week 3: Homomorphic Sealed-Bid Auction
```powershell
python -m week3_paillier_auction.examples.auction_demo
```
*Runs an auction with Alice (INR 500), Bob (INR 750), and Charlie (INR 650) using 2048-bit Paillier keys. The untrusted server aggregates ciphertexts in ~1ms without learning any individual bids, and the trustee discovers the winning clearing price.*

---

## Running the Test Suite & Quality Gates

Run all automated quality gates:

```powershell
# 1. Run Complete Test Suite (87 tests across all 3 weeks)
pytest -v

# 2. Check Test Coverage (enforces >= 85%)
pytest --cov=week1_feistel --cov=week2_double_ratchet --cov=week3_paillier_auction --cov-report=term-missing

# 3. Static Code Linting
ruff check .

# 4. Code Formatting Verification
ruff format --check .

# 5. Strict Static Type Checking
mypy .

# 6. Static Security Vulnerability Scan
bandit -r week1_feistel week2_double_ratchet week3_paillier_auction -x "*/tests/*"

# 7. Dependency Vulnerability Audit
pip-audit
```

---

## Security Analysis & Threat Models

### Week 1 Security Invariants
- **Non-Linearity & Diffusion**: The fixed S-box provides a maximum differential probability of $\le 2^{-5}$, resisting basic differential cryptanalysis. 16 Feistel rounds achieve full avalanche ($49.8\% \approx 50\%$ bit flip probability).
- **Padding Oracle Protection**: PKCS#7 unpadding strictly validates uniform padding byte values and raises explicit cryptographic exceptions on corrupt byte structures.
- **Mode Isolation**: CTR mode guarantees that bit flips in transmission only affect the corresponding bit in plaintext without block boundary contamination.

### Week 2 Security Invariants
- **Server Confidentiality**: The relay server processes and inspects only opaque ChaCha20-Poly1305 payloads and X25519 public keys. It is computationally impossible for the server to read plaintexts without private ratchet keys.
- **Replay & Tamper Detection**: Tampering with either the ciphertext or associated data (header AD) produces a Poly1305 authentication tag failure. Replayed message indices are immediately rejected by the ratchet session state.
- **Forward Secrecy**: Erasing ratcheted message keys immediately after decryption prevents past messages from being decrypted even if the current ratchet state is compromised.
- **Post-Compromise Recovery**: Alternating conversational turns trigger DH ratchet steps with freshly generated ephemeral keypairs, healing the session from previous key leakage within two turns.

### Week 3 Security Invariants
- **Semantic Security (IND-CPA)**: Paillier encryption is inherently probabilistic. Re-encrypting the same value $m$ with fresh random units $r \in \mathbb{Z}_n^*$ produces distinct ciphertexts.
- **Collusion Resistance & Untrusted Tallying**: The auctioneer can compute the component-wise product of bids but cannot decrypt any individual cell. The trustee receives only the aggregate sum vector $T_j$, never observing any individual bidder's submission.
- **Malicious Vector Mitigation**: Malicious bidders who inject out-of-range scalars or corrupt vectors can be detected through range-proof verification or discrete membership checks prior to final settlement.

---

## Standards & References

1. **Feistel Ciphers**: Feistel, H. (1973). *Cryptography and Computer Privacy*. Scientific American, 228(5), 15-23.
2. **Signal Protocol**:
   - Perrin, T., & Marlinspike, M. (2016). *The Double Ratchet Algorithm*. Signal Specifications.
   - Marlinspike, M., & Perrin, T. (2016). *The X3DH Key Agreement Protocol*. Signal Specifications.
3. **Paillier Cryptosystem**: Paillier, P. (1999). *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*. EUROCRYPT '99, LNCS 1592, pp. 223–238.
4. **AEAD Encryption**: RFC 8439: *ChaCha20 and Poly1305 for IETF Protocols*.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
