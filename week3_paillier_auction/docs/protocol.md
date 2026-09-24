# Week 3: Homomorphic Auction Protocol Specification

## 1. Discrete Price Ladder Setup

Let $P = [p_0, p_1, \dots, p_{K-1}]$ be a sorted list of $K$ discrete price levels in ascending order:
$$p_0 < p_1 < \dots < p_{K-1}$$
Example: $P = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]$ (₹ INR).

---

## 2. Vector Encoding Schemes

### A. One-Hot Vector:
For a bid $b = p_k$:
$$v_j = \begin{cases} 1 & \text{if } j = k \\ 0 & \text{if } j \neq k \end{cases}$$
The aggregate tally at price index $j$ yields the exact count of bidders who placed their bid at $p_j$.

### B. Cumulative Indicator Vector (Preferred):
For a bid $b = p_k$:
$$v_j = \begin{cases} 1 & \text{if } p_j \le b \\ 0 & \text{if } p_j > b \end{cases}$$
Example for ₹500 on a ladder with steps $[100, 250, 500, 750, 1000]$:
$$\mathbf{v} = [1, 1, 1, 0, 0]$$
The aggregate count at level $j$ represents the total demand (number of bidders willing to pay $p_j$ or higher).

---

## 3. Clearing Rules

Let $\mathbf{T} = [T_0, T_1, \dots, T_{K-1}]$ be the decrypted aggregate cumulative counts:
- $T_j = \sum_{i=1}^N v_{i, j}$

### First-Price Clearing:
1. Find the highest index $j^*$ such that $T_{j^*} \ge 1$.
2. The clearing price is $p_{j^*}$.
3. Winning bidders are identified by verifying who submitted a positive indicator at index $j^*$ (revealed conditionally, or verified through identity commitments).

### Second-Price (Vickrey) Clearing:
1. Find the highest index $j^*$ where $T_{j^*} \ge 1$ (highest bid level).
2. If $T_{j^*} > 1$ (two or more bidders tied at top price), the second price equals $p_{j^*}$.
3. If $T_{j^*} == 1$, find the next highest level $j_{second} < j^*$ where $T_{j_{second}} \ge 2$. The clearing price paid by the winner is $p_{j_{second}}$.

### Tie Resolution:
If multiple bidders bid at the highest level ($T_{j^*} > 1$), the protocol supports:
- Split allocation (if items are divisible).
- Deterministic pseudo-random tie-break using a hash of bidder commitments.
