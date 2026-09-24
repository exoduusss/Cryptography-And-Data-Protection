# Week 1: Feistel Cipher Theory & Cryptanalysis

## 1. Feistel Network Foundation

A Feistel network (Horst Feistel, 1973) is a symmetric cipher structure that divides an input block into two equal-sized halves:
$$P = (L_0, R_0)$$
For rounds $i = 0, 1, \dots, r-1$, the state transition is defined by:
$$L_{i+1} = R_i$$
$$R_{i+1} = L_i \oplus F(R_i, K_i)$$
where $F$ is a non-linear round function and $K_i$ is the round subkey derived from the master key $K$.
After $r$ rounds, the halves are typically swapped back to yield ciphertext:
$$C = (R_r, L_r)$$

### Decryption Symmetry
The fundamental advantage of a Feistel cipher is that the round function $F$ does **not** need to be invertible. Decryption is achieved by running the identical network structure with the round keys in reverse order ($K_{r-1}, \dots, K_0$):
$$R_i = L_{i+1}$$
$$L_i = R_{i+1} \oplus F(L_{i+1}, K_i) = (L_i \oplus F(R_i, K_i)) \oplus F(R_i, K_i) = L_i$$

### Luby-Rackoff Theorem (1988)
Michael Luby and Charles Rackoff proved that:
- A 3-round Feistel construction using pseudo-random functions (PRFs) is a pseudo-random permutation (PRP) secure against chosen-plaintext attacks (CPA).
- A 4-round Feistel construction is a strong PRP (SPRP) secure against adaptive chosen-plaintext and chosen-ciphertext attacks (CCA2).
In practice, practical block ciphers require additional rounds (e.g. 16 rounds) to defeat differential and linear cryptanalysis.

---

## 2. Shannon's Principles: Confusion & Diffusion

Claude Shannon's seminal 1949 paper *Communication Theory of Secrecy Systems* identified two foundational techniques:
1. **Confusion**: Obscures the relationship between the secret key and the ciphertext. Implemented primarily via non-linear substitution boxes (**S-boxes**).
2. **Diffusion**: Spreads the statistical influence of each individual plaintext bit across the entire ciphertext block and over all key bits. Implemented via **P-boxes** (permutations) and linear transformations.

---

## 3. Cryptanalysis of S-Boxes

### A. Bijectivity
An 8-bit S-box $S: \{0, 1\}^8 \to \{0, 1\}^8$ is bijective (a permutation) if:
$$\forall x, y \in \{0, 1\}^8, x \neq y \implies S(x) \neq S(y)$$
Bijectivity guarantees that no information is lost during byte substitution.

### B. Differential Uniformity
Differential cryptanalysis (Biham & Shamir, 1991) exploits non-uniform distributions in input-output XOR differences.
The **Difference Distribution Table (DDT)** entries are defined as:
$$\text{DDT}(\Delta x, \Delta y) = |\{x \in \{0, 1\}^n \mid S(x) \oplus S(x \oplus \Delta x) = \Delta y\}|$$
The **differential uniformity** $\delta$ is:
$$\delta(S) = \max_{\Delta x \neq 0, \Delta y} \text{DDT}(\Delta x, \Delta y)$$
Lower values indicate greater resistance against differential attacks. For optimal APN (almost perfect nonlinear) functions on odd dimensions $\delta = 2$; for AES S-box on 8 bits, $\delta = 4$.

### C. Nonlinearity via Walsh-Hadamard Transform
Linear cryptanalysis (Matsui, 1993) seeks affine approximations $a \cdot x \oplus b \cdot S(x) = c$.
The Walsh transform of coordinate function $f_b(x) = b \cdot S(x)$ is:
$$W_{f_b}(a) = \sum_{x \in \{0, 1\}^n} (-1)^{a \cdot x \oplus b \cdot S(x)}$$
The nonlinearity $NL(S)$ is the Hamming distance to the closest affine function:
$$NL(S) = 2^{n-1} - \frac{1}{2} \max_{a \in \{0,1\}^n, b \in \{0,1\}^n \setminus \{0\}} |W_{f_b}(a)|$$
Higher values provide stronger resistance to linear cryptanalysis (for AES, $NL = 112$).

---

## 4. Strict Avalanche Criterion (SAC) & Avalanche Effect
The Strict Avalanche Criterion (Webster & Tavares, 1985) states that flipping any single input bit must cause each output bit to invert with probability exactly $0.5$ (50% change).
Over many trials (e.g. 1,000 randomized plaintext and key single-bit flips), we evaluate:
$$\text{Diffusion}(\%) = \frac{\text{HammingDistance}(C_1, C_2)}{\text{BlockSizeBytes} \times 8} \times 100\%$$
A secure cipher approaches a mean of $50\%$ with low standard deviation as round count increases.
> [!NOTE]
> Good avalanche behavior is a necessary property for security, but it does **not** alone prove security against algebraic or slide attacks.
