"""Key Derivation Functions (KDFs) for Double Ratchet root and symmetric chains.

Educational reference implementation. Uses HKDF-SHA256 and HMAC-SHA256 per RFC 5869.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Derive next Root Key and next Chain Key from DH output.

    Args:
        rk: 32-byte current Root Key (used as HKDF salt).
        dh_out: 32-byte shared secret from X25519 DH exchange.

    Returns:
        Tuple of (next_root_key, chain_key), each 32 bytes.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b"DoubleRatchet-RootKDF-v1",
    )
    derived = hkdf.derive(dh_out)
    return derived[:32], derived[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Advance the symmetric chain to produce the next Chain Key and a single Message Key.

    Args:
        ck: 32-byte current Chain Key.

    Returns:
        Tuple of (next_chain_key, message_key), each 32 bytes.
    """
    # Using HMAC-SHA256 with distinct domain separation inputs per Signal specification
    next_ck = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    message_key = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return next_ck, message_key


def compute_safety_number(user_a_pub: bytes, user_b_pub: bytes) -> str:
    """Compute a human-readable 12-digit safety number for out-of-band identity verification.

    Sorts keys lexicographically to ensure symmetry between both parties.
    """
    ordered = sorted([user_a_pub, user_b_pub])
    digest = hashlib.sha256(ordered[0] + ordered[1]).digest()
    # Format into two groups of 6 digits
    num1 = int.from_bytes(digest[:4], "big") % 1000000
    num2 = int.from_bytes(digest[4:8], "big") % 1000000
    return f"{num1:06d} {num2:06d}"
