# 3-Week Applied Cryptography Roadmap

This repository presents three applied cryptography projects developed across three consecutive milestones, spanning symmetric design, modern authenticated ratcheting, and homomorphic privacy-preserving systems.

| Week | Milestone / System | Core Cryptographic Concepts | Deliverables & Verification | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Week 1** | **Feistel Cipher with Custom S-Boxes** | Symmetric Feistel network, custom key schedule, S-box bijectivity, differential uniformity, nonlinearity, avalanche testing, ECB/CBC/CTR modes, PKCS#7 | CLI tool, S-box analyzer, avalanche experiment with matplotlib visualization, comprehensive pytest suite (>=85% coverage) | Planned |
| **Week 2** | **E2E Encrypted Collaboration via Double Ratchet** | Extended Triple Diffie-Hellman (X3DH), Double Ratchet (X25519 DH ratchet, HKDF-SHA256 root/chain KDFs, AEAD encryption), bounded skipped-key cache, encrypted local state at rest | Untrusted FastAPI/WebSocket relay, Python client + local browser UI, out-of-order & post-compromise recovery test suite | Planned |
| **Week 3** | **Homomorphic Paillier Sealed-Bid Auction** | Additive homomorphic encryption, pure-Python Paillier cryptosystem (Miller-Rabin keygen, L(x) discrete log, homomorphic addition & scalar multiplication), private multi-party sealed-bid auction | Auctioneer (public tally), Bidders (encrypted vectors), Trustee (private key tally decryption), benchmark suite | Planned |
