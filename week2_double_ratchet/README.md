# Week 2: End-to-End Encrypted Collaboration with Double Ratchet

## Overview

This module provides a production-grade protocol implementation of the **Signal Double Ratchet** and **Extended Triple Diffie-Hellman (X3DH)** algorithms in Python 3.11+, providing End-to-End Encryption (E2EE) for 1:1 messaging and collaborative notes over an untrusted relay.

All cryptographic primitives are sourced from the audited `cryptography` library (Curve25519/X25519, Ed25519, HKDF-SHA256, and ChaCha20-Poly1305).

---

## Architectural Highlights

- **Untrusted FastAPI + WebSocket Relay**:
  The relay acts strictly as a public prekey repository and ciphertext router. Zero plaintext bytes or private keys ever touch the server.
- **Pure Cryptographic State Machine**:
  The `RatchetSession` class cleanly models the Double Ratchet state transitions, independently of networking or persistence.
- **Dual Ratcheting**:
  - **Symmetric Chain Ratchet**: Advances with each message; guarantees immediate **Forward Secrecy**.
  - **Diffie-Hellman (DH) Ratchet**: Advances when turns alternate; guarantees **Post-Compromise Recovery** (Break-in Recovery).
- **Out-of-Order Delivery**:
  A bounded skipped-key cache stores message keys for out-of-order packets up to a configurable maximum, mitigating denial-of-service memory exhaustion.
- **At-Rest State Encryption**:
  Local session databases are serialized and encrypted using PBKDF2-HMAC-SHA256 key derivation with ChaCha20-Poly1305 authenticated encryption.
- **Safety Numbers**:
  Mutual 12-digit fingerprint derivation for out-of-band identity verification.

---

## Security Invariants Verified by Tests

The automated test suite (`tests/test_security.py`) formally verifies 7 core properties:
1. **Server Confidentiality**: Server logs and storage retain 0 plaintext bytes.
2. **Distinct Key Per Message**: Every single message key is cryptographically unique.
3. **Tamper Detection**: Altering any byte in the ciphertext or header metadata fails Poly1305 verification.
4. **Replay Rejection**: Replaying a previously decrypted message is detected and rejected.
5. **Out-of-Order Delivery**: Packets arriving out of sequence decrypt within bound; packets exceeding bounds are rejected safely.
6. **Forward Secrecy**: Stolen current chain keys cannot decrypt past messages.
7. **Post-Compromise Recovery**: Ephemeral state compromise is actively healed after a single DH round-trip.

---

## Running the Demo

Execute the multi-client simulation with Alice, Bob, and the untrusted relay:
```powershell
python -m week2_double_ratchet.examples.demo
```

### Verification Gate Execution
```powershell
ruff check week2_double_ratchet
ruff format --check week2_double_ratchet
mypy week2_double_ratchet
bandit -r week2_double_ratchet -x week2_double_ratchet/tests
pytest week2_double_ratchet --cov=week2_double_ratchet --cov-fail-under=85
```
