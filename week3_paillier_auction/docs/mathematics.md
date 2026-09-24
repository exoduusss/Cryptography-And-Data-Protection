# Week 3: Paillier Cryptosystem Mathematics

## 1. Mathematical Foundations (Pascal Paillier, 1999)

The Paillier cryptosystem is an additive partially homomorphic asymmetric cryptosystem whose semantic security rests on the **Decisional Composite Residuosity Assumption (DCRA)**.

### Key Generation
1. Choose two large independent prime numbers $p$ and $q$ of equal bit-length such that $\gcd(pq, (p-1)(q-1)) = 1$.
2. Compute the RSA modulus:
   $$n = p \cdot q$$
   and Carmichael's totient function:
   $$\lambda = \text{lcm}(p - 1, q - 1) = \frac{(p - 1)(q - 1)}{\gcd(p - 1, q - 1)}$$
3. Compute $n^2$.
4. Select generator $g = n + 1 \pmod{n^2}$.
   Using $g = n + 1$ optimizes key generation and encryption because of the binomial expansion:
   $$(1 + n)^m \equiv 1 + m \cdot n \pmod{n^2}$$
5. Verify $\gcd(L(g^\lambda \bmod n^2), n) = 1$, where the function $L$ is defined as:
   $$L(u) = \frac{u - 1}{n}$$
6. Compute modular multiplier:
   $$\mu = (L(g^\lambda \bmod n^2))^{-1} \pmod n$$
   When $g = n + 1$, $g^\lambda \equiv 1 + \lambda n \pmod{n^2}$, so $L(g^\lambda \bmod n^2) \equiv \lambda \pmod n$, and thus $\mu = \lambda^{-1} \pmod n$.

- **Public Key**: $(n, g)$
- **Private Key**: $(\lambda, \mu)$

---

## 2. Encryption & Decryption

### Encryption
For a plaintext message $m \in \mathbb{Z}_n$ ($0 \le m < n$):
1. Select random $r \in \mathbb{Z}_n^*$ such that $\gcd(r, n) = 1$.
2. Compute ciphertext $c \in \mathbb{Z}_{n^2}^*$:
   $$c = g^m \cdot r^n \pmod{n^2} = (1 + m \cdot n) \cdot r^n \pmod{n^2}$$

### Decryption
Given ciphertext $c \in \mathbb{Z}_{n^2}^*$:
$$m = L(c^\lambda \bmod n^2) \cdot \mu \pmod n$$

---

## 3. Homomorphic Properties

### Homomorphic Addition of Plaintexts
Multiplying two ciphertexts in $\mathbb{Z}_{n^2}^*$ results in the addition of their corresponding plaintexts modulo $n$:
$$c_1 = g^{m_1} r_1^n \pmod{n^2}, \quad c_2 = g^{m_2} r_2^n \pmod{n^2}$$
$$c_{sum} = c_1 \cdot c_2 \equiv g^{m_1 + m_2} (r_1 r_2)^n \pmod{n^2}$$
$$D(c_{sum}) = (m_1 + m_2) \pmod n$$

### Scalar Multiplication of Ciphertext
Raising a ciphertext to a plaintext scalar constant $k \in \mathbb{Z}_n$:
$$c^k \equiv (g^m r^n)^k \equiv g^{k \cdot m} (r^k)^n \pmod{n^2}$$
$$D(c^k) = (k \cdot m) \pmod n$$

### Re-randomization
Given ciphertext $c = E(m, r_1)$, selecting fresh $r_2 \in \mathbb{Z}_n^*$ and computing:
$$c' = c \cdot r_2^n \pmod{n^2}$$
yields a fresh ciphertext $c'$ that decrypts to the identical plaintext $m$ while being indistinguishable from any other encryption of $m$.

---

## 4. Range and Overflow Considerations
Plaintexts are elements of the finite field $\mathbb{Z}_n$. If the sum of inputs $\sum m_i \ge n$, the sum wraps around modulo $n$ (modular overflow). Because $n$ is at least 512 bits (or 2048 bits in production), the sum of small integer values (e.g., bid amounts or binary tally indicators) will never approach $n$, strictly eliminating overflow risk.
