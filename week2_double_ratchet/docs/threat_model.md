# Week 2: Threat Model & Security Boundaries

## Adversary Model

We assume an active, untrusted network and an honest-but-curious or malicious relay server:
- The relay server can inspect, delay, drop, or reorder all network packets.
- The relay server can log all metadata (source/destination IP, timestamps, message lengths, sender and recipient user IDs).
- The network adversary can attempt to replay past packets or inject tampered bytes.

---

## Security Guarantees & Non-Guarantees

### What the Untrusted Relay CANNOT See:
1. **Plaintext Message Content**: All payloads are encrypted using ChaCha20-Poly1305.
2. **Plaintext Shared Notes / State**: Synchronized document edits are wrapped in the same ratchet ciphertext.
3. **Past Message Keys (Forward Secrecy)**: Once a message is decrypted and its key consumed, even total compromise of the client's current private keys cannot decrypt historical transcripts.
4. **Future Message Keys (Post-Compromise Recovery / Healing)**: If ephemeral ratchet state is leaked, the adversary loses interception capabilities as soon as both parties exchange a single new DH round-trip.

### What the Untrusted Relay CAN See (Metadata Leakage):
1. **Communication Graph**: Who communicates with whom (`sender_id` and `recipient_id`).
2. **Traffic Timing & Frequency**: Exact timestamps when messages are submitted and forwarded.
3. **Payload Length**: Approximate byte lengths of encrypted messages (padding can mitigate, but size distribution remains observable).

---

## Threat Mitigations Matrix

| Attack / Threat | Defense Implemented | Residual Risk |
| :--- | :--- | :--- |
| **Server Eavesdropping** | End-to-end ChaCha20-Poly1305 encryption. Private keys never leave the client. | Metadata (traffic analysis) visible to server. |
| **Ciphertext Tampering** | Poly1305 MAC over ciphertext and associated data. | Tampered messages fail decryption. |
| **Header Tampering** | Header parameters (`dh_pub`, `pn`, `n`) bound into Associated Data (AD). | Any altered counter causes immediate MAC failure. |
| **Replay Attacks** | Message counters and single-use message key deletion. | Replayed messages are rejected as already consumed. |
| **Out-of-Order Packets** | Bounded skipped-key store caches up to $M$ keys (default: 1000). | Packets arriving past max bound are rejected. |
| **State Theft at Rest** | Session state encrypted with PBKDF2/Scrypt passphrase derivation. | Weak user passphrases vulnerable to dictionary attacks. |
| **Man-in-the-Middle (MitM)** | Ed25519 signature on prekeys; safety number fingerprint verification. | Users must compare safety numbers out-of-band. |

## Out of Scope:
- Physical endpoint malware / keylogger on client device.
- Timing analysis on server traffic correlation.
- Group messaging protocols (MLS / Sender Keys).
