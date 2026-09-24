# Week 2: E2E Encrypted Collaboration Architecture

## System Architecture

The collaboration tool is partitioned into three decoupled tiers:
1. **Cryptographic Core (`week2_double_ratchet/crypto/`)**: A pure, synchronous state machine with zero networking or storage dependencies.
2. **Untrusted WebSocket Relay (`week2_double_ratchet/backend/`)**: FastAPI server acting as a dumb mailbox / message switchboard.
3. **Client Engine & Local UI (`week2_double_ratchet/client/`)**: Python daemon that orchestrates crypto, websocket networking, and serves a local web UI.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Alice (Client A)
    participant Relay as Untrusted Server
    actor Bob as Bob (Client B)

    Note over Bob,Relay: Initial Registration
    Bob->>Relay: Upload Prekey Bundle (IK_B, SPK_B, OPK_B_list)

    Note over Alice,Relay: X3DH Key Agreement
    Alice->>Relay: Request Bob's Prekey Bundle
    Relay-->>Alice: Prekey Bundle (IK_B, SPK_B, OPK_B)
    Note over Alice: Computes DH1, DH2, DH3, DH4 -> RootKey (RK)

    Note over Alice,Bob: 1:1 Encrypted Messaging & Ratcheting
    Alice->>Relay: WebSocket: Send RatchetMessage(Header, Ciphertext)
    Relay->>Bob: WebSocket: Forward RatchetMessage
    Note over Bob: Verifies Header via AD, Steps Ratchet, Decrypts Payload

    Bob->>Relay: WebSocket: Reply RatchetMessage(NewHeader, Ciphertext)
    Relay->>Alice: WebSocket: Forward RatchetMessage
    Note over Alice: Steps DH Ratchet (Post-Compromise Recovery Active)
```

## State Machine Layout

```mermaid
stateDiagram-v2
    [*] --> Uninitialized
    Uninitialized --> ActiveSession: Complete X3DH Handshake
    ActiveSession --> ActiveSession: Send Message (Advance Sending Chain)
    ActiveSession --> ActiveSession: Receive Message (Same DH: Advance Receiving Chain)
    ActiveSession --> ActiveSession: Receive Message (New DH: Advance DH Ratchet & Derive Chains)
    ActiveSession --> ActiveSession: Out-of-Order Message (Consume Skipped-Key)
    ActiveSession --> EncryptedAtRest: Encrypt with Passphrase (PBKDF2/Scrypt)
    EncryptedAtRest --> ActiveSession: Decrypt with Passphrase
```

## Collaboration Features
1. **1:1 Encrypted Chat**: Real-time bidirectional messaging over WebSocket.
2. **Encrypted Collaborative Notes**: Document updates (JSON patches/CRDT-like deltas) transmitted as encrypted ratchet messages over pairwise sessions.
3. **Interactive Ratchet Inspector**: Visualizes Root Key fingerprints, sending/receiving counters, and DH key turns in the local web UI.
