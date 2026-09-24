# Week 1: Feistel Architecture & System Design

## Architecture Overview

The system is architected as an extensible block cipher framework separating:
1. **Generic Feistel Round Structure**
2. **Pluggable Round Functions & S-Boxes**
3. **Deterministic Key Schedule**
4. **Cipher Modes of Operation (ECB, CBC, CTR) with PKCS#7 Padding**
5. **Cryptanalytic & Evaluation Utilities**

```mermaid
flowchart TD
    subgraph Master Key & Key Schedule
        MK[Master Key: 128-bit] --> KDF[HKDF-SHA256 Expander]
        KDF --> RKeys["Round Keys: K_0, K_1, ..., K_r-1"]
    end

    subgraph Feistel Round Structure
        P[Plaintext Block: 64-bit] --> Split["Split into L_0 (32-bit), R_0 (32-bit)"]
        Split --> R0[Round 0]
        RKeys -.->|K_0| R0
        R0 --> R1[Round 1]
        RKeys -.->|K_1| R1
        R1 --> Dots[...]
        Dots --> Rn["Round r-1"]
        RKeys -.->|K_r-1| Rn
        Rn --> Swap["Swap Halves (R_r, L_r)"]
        Swap --> C[Ciphertext Block: 64-bit]
    end

    subgraph Pluggable Round Function F
        R_in[Input Half 32-bit] --> KeyMix["XOR with Round Key K_i"]
        KeyMix --> SBoxGroup["Byte Substitution (4x S-Box lookups)"]
        SBoxGroup --> Perm["Bitwise Permutation P-Box"]
        Perm --> Out[Output 32-bit]
    end
```

## Modular Components

### 1. Pluggable S-Boxes (`substitution.py`)
- **Fixed S-box**: Derived from Rijndael $\mathbb{F}_{2^8}$ inversion with affine transformation.
- **Key-Dependent S-box**: Dynamically constructed per master key via Fisher-Yates shuffle seeded with SHA-256 HKDF output.
- **Custom Hybrid S-box**: Non-linear polynomial map $x \mapsto x^7 + 0x63 \pmod{256}$ with fixed-point elimination.

### 2. P-Boxes (`permutation.py`)
- 32-bit diffusion permutation that diffuses each output bit of an S-box into different S-boxes in the subsequent round.

### 3. Key Schedule (`key_schedule.py`)
- Uses HKDF (RFC 5869) with SHA-256 to extract and expand 128-bit master keys into $r$ independent 32-bit round subkeys.

### 4. Modes of Operation (`modes.py`)
- **ECB**: Electronic Codebook (independent block encryption).
- **CBC**: Cipher Block Chaining ($C_i = E_K(P_i \oplus C_{i-1})$) using cryptographic IVs (`secrets.token_bytes`).
- **CTR**: Counter mode ($C_i = P_i \oplus E_K(Nonce \parallel Counter)$), parallelizable and streaming.
