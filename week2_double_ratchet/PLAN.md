# Week 2 Implementation Plan: E2E Encrypted Collaboration Tool with Double Ratchet

## Overview
Implement an End-to-End Encrypted (E2EE) messaging and collaboration engine adhering to the Signal Double Ratchet and X3DH protocol specifications. The system is architected into three strictly isolated layers:
1. **Cryptographic Core (`crypto/`)**: Pure state machine implementing X3DH key exchange, DH ratcheting (X25519), symmetric KDF chains (HKDF-SHA256), AEAD encryption with Associated Data (ChaCha20-Poly1305), bounded skipped-key cache, and encrypted session serialization.
2. **Untrusted Relay Server (`backend/`)**: FastAPI + WebSocket relay that only sees opaque ciphertexts, sender/recipient IDs, and public prekey bundles. Zero plaintext or private keys ever touch the server.
3. **Client & UI (`client/`)**: Python client maintaining cryptographic state, local database, and providing a local browser web UI for 1:1 chat and encrypted collaborative notes.

---

## Day-by-Day Checklist & Work Stages

### Day 1: Protocol Research & Requirements
- [x] Study Signal Double Ratchet specification (Perrin & Marlinspike, 2016) and X3DH specification.
- [x] Define protocol data structures: PrekeyBundle, MessageHeader, RatchetMessage, SkippedKeyStore.
- [x] Specify security invariants: forward secrecy, post-compromise recovery (break-in recovery), AEAD integrity.
- **Expected Commit**: `docs(w2-ratchet): document X3DH and Double Ratchet protocol specifications`

### Day 2: Architecture & Threat Model Documentation
- [x] Write `docs/architecture.md`: Mermaid sequence diagrams for X3DH initial handshake, DH ratchet turns, and WebSocket message relaying.
- [x] Write `docs/protocol.md`: Exact state transitions, KDF inputs, header structure, and associated data bindings.
- [x] Write `docs/threat_model.md`: Explicit threat model (what untrusted relay sees: metadata, packet timing, message length; what it cannot see: plaintext payloads, future/past keys).
- **Expected Commit**: `docs(w2-ratchet): add architecture, protocol specification, and threat model documentation`

### Day 3: Cryptographic Primitives & State Machine
- [x] `crypto/identity.py`: Identity keys (Ed25519 for signing, X25519 for DH exchange), prekey generation and signing.
- [x] `crypto/kdf.py`: HKDF-SHA256 derivations for Root KDF, Chain KDF (message key and next chain key), and header authentication.
- [x] `crypto/encryption.py`: AEAD wrapper using ChaCha20-Poly1305 with header serialization as Associated Data (AD).
- [x] `crypto/x3dh.py`: Extended Triple Diffie-Hellman (X3DH) Alice (initiator) and Bob (receiver) shared secret agreement.
- [x] `crypto/double_ratchet.py`: Pure Double Ratchet state machine (`RatchetSession`) managing Root Key, Sending/Receiving chains, DH key pairs, message counters, and bounded skipped keys.
- **Expected Commit**: `feat(w2-ratchet): implement core cryptographic primitives and Double Ratchet state machine`

### Day 4: Out-of-Order Handling, Serialization & At-Rest Encryption
- [x] Bounded skipped keys cache (configurable maximum, e.g. 1000 keys) allowing receipt of out-of-order and delayed messages.
- [x] `crypto/serialization.py`: Session state serialization to JSON and encrypted at rest with passphrase-derived key via Scrypt/PBKDF2 + AES-GCM/ChaCha20-Poly1305.
- [x] Safety number / cryptographic fingerprint calculation for out-of-band identity verification.
- **Expected Commit**: `feat(w2-ratchet): add bounded skipped-key cache, encrypted persistence, and safety numbers`

### Day 5: Untrusted Relay Backend, Python Client & Local UI
- [x] `backend/models.py`: Pydantic models for prekey bundles, registered users, and encrypted relay messages.
- [x] `backend/server.py` & `backend/websocket.py`: FastAPI server with HTTP endpoints for registration/prekeys and WebSocket endpoint for live ciphertext relaying.
- [x] `client/client.py`: Python E2EE client connecting to relay, handling X3DH handshake, messaging, and encrypted shared notes.
- [x] `client/ui/`: Lightweight local HTML/CSS/JS interface served locally by the client displaying chat, notes, and visual ratchet state (no browser crypto).
- [x] `examples/demo.py`: Automated multi-client demo (Alice and Bob) demonstrating handshake, out-of-order receipt, ratchet updates, and inspecting untrusted server logs.
- **Expected Commit**: `feat(w2-ratchet): implement FastAPI relay backend, Python client, local UI, and interactive demo`

### Day 6: Security Verification Suite
- [x] `tests/test_encryption.py`: AEAD encryption/decryption, header tampering rejection, ciphertext corruption.
- [x] `tests/test_ratchet.py`: Linear exchange, alternating turns, DH ratchet key stepping, distinct message keys.
- [x] `tests/test_session.py`: State serialization roundtrips, wrong passphrase rejection, encrypted state integrity.
- [x] `tests/test_security.py`:
  1. Server confidentiality: Server storage/logs contain 0 plaintext bytes.
  2. Distinct keys per message: Every message key is unique.
  3. Tamper detection: Inverted header or payload bits fail MAC check.
  4. Replay rejection: Replaying an old message fails.
  5. Out-of-order delivery: Messages arriving out of order decrypt within bound; safe rejection beyond bound.
  6. Forward secrecy: Past message keys cannot be derived from current state.
  7. Post-compromise recovery: After state compromise, a single DH round-trip heals security against passive listeners.
- **Expected Commit**: `test(w2-ratchet): add comprehensive security, ratchet, and server confidentiality tests`

### Day 7: Documentation, Verification Gate & Release Tag
- [x] Write `week2_double_ratchet/README.md`.
- [x] Run Verification Gate:
  1. `ruff check .`
  2. `ruff format --check .`
  3. `mypy week2_double_ratchet`
  4. `bandit -r week2_double_ratchet -x week2_double_ratchet/tests`
  5. `pytest week2_double_ratchet --cov=week2_double_ratchet --cov-fail-under=85`
  6. `python -m week2_double_ratchet.examples.demo`
  7. Full regression `pytest` from repo root (Week 1 + Week 2).
- [x] Merge `feat/w2-double-ratchet` into `develop`.
- [x] Merge `develop` into `main` and tag `v0.2.0-week2`.
- **Expected Commit**: `chore(w2-ratchet): finalize week 2 verification gate and release`

---

## Definition of Done
1. All files typed with strict mypy compliance and docstrings.
2. 100% pass on all verification gate commands.
3. Code coverage strictly $\ge 85\%$.
4. All 7 security invariant tests pass without skips or mocks.
5. Local Git tag `v0.2.0-week2` verified.
