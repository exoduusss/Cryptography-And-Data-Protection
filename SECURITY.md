# Security Policy

## Scope and Educational Disclaimer

> [!WARNING]
> This repository is built for educational, research, and portfolio purposes (coursework, viva, and technical demonstrations).
> While the cryptographic designs follow standard protocol specifications (e.g., Signal Double Ratchet, X3DH, NIST guidelines, Paillier EUROCRYPT 1999):
> - Hand-rolled algorithms (such as the Week 1 Feistel cipher and the Week 3 pure-Python Paillier implementation) are **NOT hardened for production use**.
> - Python integer arithmetic and general-purpose implementations **do not provide constant-time guarantees** and may be susceptible to timing side-channel attacks.
> - High-assurance systems must use verified, audited hardware/cryptographic libraries (such as Libsodium, OpenSSL, or OS-native cryptography).

## Reporting Security Vulnerabilities

We appreciate responsible disclosure. If you discover a security vulnerability or algorithmic weakness in this codebase:

1. **Do not create a public GitHub issue.**
2. Send an email describing the vulnerability, proof of concept, and impact to the repository maintainer.
3. We will acknowledge receipt within 48 hours and work with you on analysis and remediation before any public disclosure.

## Security Posture & Assumptions

| Component | Security Level | Core Assumptions / Limitations |
| :--- | :--- | :--- |
| **Week 1: Feistel Cipher** | Educational Toy Cipher | No authenticated encryption (MAC/AEAD); vulnerable to chosen-ciphertext attacks unless combined with HMAC; timing non-constant; small blocks vulnerable to birthday attacks. |
| **Week 2: Double Ratchet & X3DH** | Robust Protocol / Educational Server | Uses vetted primitives (`cryptography` X25519, Ed25519, HKDF-SHA256, ChaCha20-Poly1305 / AES-GCM); untrusted relay cannot read payloads; does leak communication metadata (traffic timing, packet size, message frequency, sender/recipient IDs). |
| **Week 3: Paillier Auction** | Educational Homomorphic System | Additive homomorphic privacy under CPA; honest-but-curious server / non-colluding trustee assumption; without ZK validity proofs, malicious bidders could inject arbitrary vector values; timing side channels exist in pure-Python modular exponentiation. |
