# Week 3: Sealed-Bid Auction Architecture

## Multi-Party Architecture

In an auction, computing the winning bid requires comparisons ($b_1 > b_2$). However, **Paillier cannot compare ciphertexts directly** without decrypting them.

To preserve complete bid secrecy without decrypting individual bids, we partition the system into three distinct cryptographic roles:
1. **Bidders**: Each bidder selects a bid from a discrete price ladder $P = [p_0, p_1, \dots, p_{K-1}]$ and submits an **encrypted cumulative indicator vector**:
   $$\mathbf{v} = [E(v_0), E(v_1), \dots, E(v_{K-1})]$$
   where $v_j = 1$ if $\text{bid} \ge p_j$, and $0$ otherwise.
2. **Untrusted Auctioneer**: Holds the **Public Key only**. Collects all bidder vectors and computes the component-wise homomorphic sum:
   $$C_j = \prod_{i=1}^N E(v_{i, j}) \pmod{n^2}$$
   $C_j$ is the encryption of the total count of bidders willing to pay price $p_j$ or higher.
3. **Independent Trustee**: Holds the **Private Key**. Decrypts **ONLY the aggregated vector** $\mathbf{C}$:
   $$\mathbf{T} = [D(C_0), D(C_1), \dots, D(C_{K-1})]$$
   The Trustee never sees individual vectors and never has access to the auction database.

```mermaid
sequenceDiagram
    autonumber
    actor BidderA as Bidder Alice (₹500)
    actor BidderB as Bidder Bob (₹750)
    actor BidderC as Bidder Charlie (₹650)
    participant Auctioneer as Untrusted Auctioneer (Public Key Only)
    participant Trustee as Independent Trustee (Private Key Only)

    Note over Trustee,Auctioneer: Setup Phase
    Trustee->>Trustee: Generate Keypair: Public (n, g), Private (lambda, mu)
    Trustee->>Auctioneer: Publish Public Key (n, g) & Price Ladder

    Note over BidderA,BidderC: Bidding Phase (Encrypted Vectors)
    BidderA->>Auctioneer: Submit Encrypted Cumulative Vector E(v_A)
    BidderB->>Auctioneer: Submit Encrypted Cumulative Vector E(v_B)
    BidderC->>Auctioneer: Submit Encrypted Cumulative Vector E(v_C)

    Note over Auctioneer: Tallying Phase (Homomorphic Multiplication)
    Auctioneer->>Auctioneer: Component-wise Multiply: C_j = Prod(E(v_i,j)) mod n^2

    Note over Auctioneer,Trustee: Decryption Phase (Aggregate Only)
    Auctioneer->>Trustee: Send Aggregated Vector [C_0, C_1, ..., C_K-1]
    Note over Trustee: Decrypts ONLY aggregate counts: [T_0, T_1, ..., T_K-1]
    Trustee-->>Auctioneer: Return Plaintext Counts [T_0, T_1, ..., T_K-1]

    Note over Auctioneer: Winner Determination
    Auctioneer->>Auctioneer: Identify Highest Price with T_j >= 1 (Winner: Bob at ₹750)
```
