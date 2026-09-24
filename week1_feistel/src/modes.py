"""Block Cipher Modes of Operation: ECB, CBC, and CTR with PKCS#7 padding.

Educational reference implementation. Not for production use.
"""

from __future__ import annotations

import abc
import os

from week1_feistel.src.feistel import FeistelCipher
from week1_feistel.src.utils import pkcs7_pad, pkcs7_unpad


class BaseMode(abc.ABC):
    """Abstract base class for block cipher operational modes."""

    def __init__(self, cipher: FeistelCipher) -> None:
        self.cipher = cipher
        self.block_size = cipher.block_size

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt arbitrary plaintext bytes."""
        ...

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext and return plaintext."""
        ...


class ECBMode(BaseMode):
    """Electronic Codebook (ECB) Mode.

    WARNING: ECB mode does not provide semantic security! Identical plaintext
    blocks result in identical ciphertext blocks.
    """

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = pkcs7_pad(plaintext, self.block_size)
        out = bytearray()
        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            out.extend(self.cipher.encrypt_block(block))
        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) == 0 or len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Ciphertext length must be a non-zero multiple of {self.block_size}")
        out = bytearray()
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            out.extend(self.cipher.decrypt_block(block))
        return pkcs7_unpad(bytes(out), self.block_size)


class CBCMode(BaseMode):
    """Cipher Block Chaining (CBC) Mode.

    Formulas:
        C_0 = E_K(P_0 ^ IV)
        C_i = E_K(P_i ^ C_{i-1})
    Output format:
        IV (block_size bytes) || Ciphertext Blocks
    """

    def encrypt(self, plaintext: bytes, iv: bytes | None = None) -> bytes:
        if iv is None:
            iv = os.urandom(self.block_size)
        elif len(iv) != self.block_size:
            raise ValueError(f"IV must be exactly {self.block_size} bytes, got {len(iv)}")

        padded = pkcs7_pad(plaintext, self.block_size)
        out = bytearray(iv)
        prev = iv

        for i in range(0, len(padded), self.block_size):
            block = padded[i : i + self.block_size]
            # XOR with previous ciphertext block
            xored = bytes(b ^ p for b, p in zip(block, prev, strict=True))
            enc = self.cipher.encrypt_block(xored)
            out.extend(enc)
            prev = enc

        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < self.block_size * 2:
            raise ValueError(
                f"Ciphertext too short for CBC (minimum {self.block_size * 2} bytes with IV)"
            )
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Ciphertext length must be a multiple of {self.block_size}")

        iv = ciphertext[: self.block_size]
        ct_blocks = ciphertext[self.block_size :]

        out = bytearray()
        prev = iv

        for i in range(0, len(ct_blocks), self.block_size):
            block = ct_blocks[i : i + self.block_size]
            dec = self.cipher.decrypt_block(block)
            plain_block = bytes(d ^ p for d, p in zip(dec, prev, strict=True))
            out.extend(plain_block)
            prev = block

        return pkcs7_unpad(bytes(out), self.block_size)


class CTRMode(BaseMode):
    """Counter (CTR) Mode.

    Turns the block cipher into a stream cipher by encrypting successive counter blocks.
    Does not require PKCS#7 padding.

    Output format:
        Nonce (half_size bytes = 4 bytes) || Ciphertext Stream
    Counter block format:
        Nonce (4 bytes) || Counter (4 bytes big-endian)
    """

    def __init__(self, cipher: FeistelCipher) -> None:
        super().__init__(cipher)
        self.nonce_size = self.block_size // 2  # 4 bytes
        self.counter_size = self.block_size - self.nonce_size  # 4 bytes

    def encrypt(self, plaintext: bytes, nonce: bytes | None = None) -> bytes:
        if nonce is None:
            nonce = os.urandom(self.nonce_size)
        elif len(nonce) != self.nonce_size:
            raise ValueError(f"Nonce must be exactly {self.nonce_size} bytes, got {len(nonce)}")

        out = bytearray(nonce)
        counter = 0

        for i in range(0, len(plaintext), self.block_size):
            chunk = plaintext[i : i + self.block_size]
            ctr_bytes = counter.to_bytes(self.counter_size, byteorder="big")
            counter_block = nonce + ctr_bytes
            keystream = self.cipher.encrypt_block(counter_block)

            # XOR plaintext chunk with keystream
            xored = bytes(p ^ k for p, k in zip(chunk, keystream[: len(chunk)], strict=True))
            out.extend(xored)
            counter = (counter + 1) % (1 << (self.counter_size * 8))

        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < self.nonce_size:
            raise ValueError(
                f"Ciphertext too short for CTR mode (minimum {self.nonce_size} bytes for nonce)"
            )

        nonce = ciphertext[: self.nonce_size]
        payload = ciphertext[self.nonce_size :]

        out = bytearray()
        counter = 0

        for i in range(0, len(payload), self.block_size):
            chunk = payload[i : i + self.block_size]
            ctr_bytes = counter.to_bytes(self.counter_size, byteorder="big")
            counter_block = nonce + ctr_bytes
            keystream = self.cipher.encrypt_block(counter_block)

            xored = bytes(c ^ k for c, k in zip(chunk, keystream[: len(chunk)], strict=True))
            out.extend(xored)
            counter = (counter + 1) % (1 << (self.counter_size * 8))

        return bytes(out)
