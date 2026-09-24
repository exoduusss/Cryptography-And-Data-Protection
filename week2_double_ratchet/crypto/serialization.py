"""Session state serialization and at-rest encryption via PBKDF2/Scrypt.

Educational reference implementation. Uses vetted primitives from `cryptography`.
"""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from week2_double_ratchet.crypto.double_ratchet import RatchetSession


def serialize_session(session: RatchetSession) -> dict[str, Any]:
    """Serialize RatchetSession state into a JSON-encodable dictionary."""
    # Export our_dh_priv raw bytes
    dhs_raw = session.dhs.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Convert skipped keys map
    skipped_serialized = [
        {"dh_pub": k[0].hex(), "n": k[1], "mk": v.hex()} for k, v in session.mk_skipped.items()
    ]

    return {
        "dhs": dhs_raw.hex(),
        "dhr": session.dhr.hex() if session.dhr is not None else None,
        "rk": session.rk.hex(),
        "cks": session.cks.hex() if session.cks is not None else None,
        "ckr": session.ckr.hex() if session.ckr is not None else None,
        "ns": session.ns,
        "nr": session.nr,
        "pn": session.pn,
        "max_skip": session.max_skip,
        "mk_skipped": skipped_serialized,
    }


def deserialize_session(state: dict[str, Any]) -> RatchetSession:
    """Reconstitute a RatchetSession from a state dictionary."""
    dhs = X25519PrivateKey.from_private_bytes(bytes.fromhex(state["dhs"]))
    dhr = bytes.fromhex(state["dhr"]) if state["dhr"] is not None else None
    rk = bytes.fromhex(state["rk"])

    session = RatchetSession(
        shared_key=rk,
        our_dh_priv=dhs,
        their_dh_pub_bytes=dhr,
        is_initiator=False,  # Reconstitute manually below
        max_skip=state.get("max_skip", 1000),
    )
    session.dhr = dhr
    session.cks = bytes.fromhex(state["cks"]) if state["cks"] is not None else None
    session.ckr = bytes.fromhex(state["ckr"]) if state["ckr"] is not None else None
    session.ns = int(state["ns"])
    session.nr = int(state["nr"])
    session.pn = int(state["pn"])

    skipped_map: dict[tuple[bytes, int], bytes] = {}
    for item in state.get("mk_skipped", []):
        k = (bytes.fromhex(item["dh_pub"]), int(item["n"]))
        skipped_map[k] = bytes.fromhex(item["mk"])
    session.mk_skipped = skipped_map

    return session


def encrypt_session_at_rest(session: RatchetSession, passphrase: str) -> bytes:
    """Encrypt session state at rest with a passphrase using
    PBKDF2-HMAC-SHA256 and ChaCha20-Poly1305.

    Returns:
        Salt (16 bytes) || Nonce (12 bytes) || Ciphertext + Tag
    """
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    state_dict = serialize_session(session)
    payload = json.dumps(state_dict).encode("utf-8")

    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, payload, associated_data=b"ratchet-state-at-rest-v1")
    return salt + nonce + ciphertext


def decrypt_session_at_rest(encrypted_blob: bytes, passphrase: str) -> RatchetSession:
    """Decrypt session state from encrypted storage using passphrase.

    Raises:
        ValueError: If passphrase is wrong or data is tampered.
    """
    if len(encrypted_blob) < 16 + 12 + 16:
        raise ValueError("Encrypted session data is corrupt or incomplete")

    salt = encrypted_blob[:16]
    nonce = encrypted_blob[16:28]
    ciphertext = encrypted_blob[28:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    aead = ChaCha20Poly1305(key)
    try:
        decrypted_json = aead.decrypt(
            nonce, ciphertext, associated_data=b"ratchet-state-at-rest-v1"
        )
    except InvalidTag as e:
        raise ValueError("Decryption failed: incorrect passphrase or corrupted data") from e

    state_dict = json.loads(decrypted_json.decode("utf-8"))
    return deserialize_session(state_dict)
