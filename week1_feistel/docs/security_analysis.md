# Week 1: Security Analysis & Cryptographic Limitations

> [!WARNING]
> This Feistel cipher implementation is strictly for **educational and research purposes**. It is not designed or audited for securing production data.

## Cryptographic Threats & Defenses

| Threat / Attack Vector | Severity | Analysis & Mitigation |
| :--- | :--- | :--- |
| **Differential Cryptanalysis** | High | Differential uniformity $\delta$ of our S-boxes is analyzed. 16 Feistel rounds ensure differential characteristics fall below $2^{-64}$. |
| **Linear Cryptanalysis** | High | S-box Walsh-Hadamard nonlinearity is calculated. Linear approximation probabilities decay exponentially over 16 rounds. |
| **ECB Mode Pattern Leakage** | High | Identical plaintext blocks encrypt to identical ciphertext blocks. ECB is implemented for academic comparison only; CBC and CTR are provided for realistic use. |
| **Padding Oracle Attacks** | High | Classical CBC mode without authentication is vulnerable to padding oracle attacks (Vaudenay 2002) if decryption errors differentiate invalid padding from MAC failures. |
| **Ciphertext Tampering** | Critical | Unauthenticated modes (ECB, CBC, CTR) do not guarantee integrity. Bit flips in CTR ciphertext cause direct bit flips in plaintext without detection. Production systems require AEAD (e.g. ChaCha20-Poly1305, AES-GCM). |
| **Timing Side-Channels** | Moderate | Python table lookups (`S[x]`) and arbitrary-precision integer operations are not constant-time and are vulnerable to cache and timing analysis. |
| **Birthday Attacks** | Moderate | 64-bit block size means collisions in CBC mode occur around $2^{32}$ blocks ($\approx 32\text{ GB}$). Modern standards mandate 128-bit blocks (AES). |

## Assumptions & Cryptographic Limitations
1. **Unauthenticated Encryption**: No Message Authentication Code (MAC) is attached. Integrity and authenticity are not guaranteed.
2. **Key Length**: Default is 128 bits. Shorter keys are rejected to prevent brute-force recovery.
3. **Execution Environment**: No guarantees of constant-time execution on CPU hardware.
