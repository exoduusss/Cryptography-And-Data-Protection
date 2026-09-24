"""Paillier partially homomorphic cryptosystem engine.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass

from week3_paillier_auction.crypto.key_generation import generate_keypair_components
from week3_paillier_auction.crypto.math_utils import l_function, mod_inverse


@dataclass(frozen=True)
class PaillierPublicKey:
    """Public key for the Paillier cryptosystem."""

    n: int
    g: int | None = None

    def __post_init__(self) -> None:
        if self.g is None:
            object.__setattr__(self, "g", self.n + 1)
        object.__setattr__(self, "n_squared", self.n * self.n)

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    def encrypt(self, m: int, r: int | None = None) -> int:
        """Encrypt a plaintext message m in range [0, n - 1].

        Args:
            m: Plaintext integer.
            r: Optional randomness in Z_n^* (if None, sampled securely).

        Returns:
            Ciphertext integer in Z_{n^2}^*.

        Raises:
            ValueError: If m is out of range [0, n - 1].
        """
        if m < 0 or m >= self.n:
            raise ValueError(f"Plaintext message {m} is out of range [0, n - 1]")

        n_sq = self.n * self.n

        if r is None:
            while True:
                r_cand = secrets.randbelow(self.n - 1) + 1
                if math.gcd(r_cand, self.n) == 1:
                    r = r_cand
                    break
        else:
            if r <= 0 or r >= self.n or math.gcd(r, self.n) != 1:
                raise ValueError("Random factor r must be in Z_n^*")

        # Optimized g^m mod n^2 using (1 + n)^m = (1 + m*n) mod n^2
        gm = (1 + m * self.n) % n_sq
        rn = pow(r, self.n, n_sq)
        return (gm * rn) % n_sq

    def homomorphic_add(self, c1: int, c2: int) -> int:
        """Homomorphic addition: E(m1) * E(m2) mod n^2 = E(m1 + m2 mod n)."""
        n_sq = self.n * self.n
        return (c1 * c2) % n_sq

    def scalar_multiply(self, c: int, scalar: int) -> int:
        """Homomorphic scalar multiplication: E(m)^k mod n^2 = E(k * m mod n)."""
        n_sq = self.n * self.n
        if scalar < 0:
            inv_c = mod_inverse(c, n_sq)
            return pow(inv_c, -scalar, n_sq)
        return pow(c, scalar, n_sq)

    def re_randomize(self, c: int, r: int | None = None) -> int:
        """Re-randomize ciphertext: c' = c * r^n mod n^2."""
        n_sq = self.n * self.n
        if r is None:
            while True:
                r_cand = secrets.randbelow(self.n - 1) + 1
                if math.gcd(r_cand, self.n) == 1:
                    r = r_cand
                    break
        rn = pow(r, self.n, n_sq)
        return (c * rn) % n_sq


@dataclass(frozen=True)
class PaillierPrivateKey:
    """Private key for the Paillier cryptosystem."""

    public_key: PaillierPublicKey
    lambda_val: int
    mu: int

    def decrypt(self, c: int) -> int:
        """Decrypt ciphertext c back to plaintext message m.

        Args:
            c: Ciphertext integer in Z_{n^2}^*.

        Returns:
            Plaintext integer m in [0, n - 1].

        Raises:
            ValueError: If ciphertext is invalid or outside valid range.
        """
        n = self.public_key.n
        n_sq = n * n

        if c <= 0 or c >= n_sq:
            raise ValueError(f"Ciphertext {c} is out of valid range (0, n^2)")

        # Compute u = c^lambda mod n^2
        u = pow(c, self.lambda_val, n_sq)
        l_val = l_function(u, n)
        return (l_val * self.mu) % n


def generate_paillier_keypair(
    key_size: int = 1024,
) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generate a fresh Paillier keypair of specified bit length."""
    comps = generate_keypair_components(key_size=key_size)
    pub_key = PaillierPublicKey(n=comps["n"], g=comps["g"])
    priv_key = PaillierPrivateKey(
        public_key=pub_key,
        lambda_val=comps["lambda_val"],
        mu=comps["mu"],
    )
    return pub_key, priv_key
