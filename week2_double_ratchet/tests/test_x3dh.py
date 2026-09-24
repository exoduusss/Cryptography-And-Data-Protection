"""Unit tests for the X3DH key agreement protocol."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from week2_double_ratchet.crypto.identity import IdentityKeyPair, PreKeyBundle
from week2_double_ratchet.crypto.kdf import compute_safety_number
from week2_double_ratchet.crypto.x3dh import x3dh_initiator, x3dh_receiver


def test_x3dh_full_agreement_with_opk() -> None:
    alice_id = IdentityKeyPair("alice")
    bob_id = IdentityKeyPair("bob")

    bob_spk_priv, bob_spk_pub, bob_spk_sig = bob_id.create_signed_prekey()
    bob_opk_pairs = bob_id.create_one_time_prekeys(count=2)
    bob_opk_privs = {pub: priv for priv, pub in bob_opk_pairs}
    bob_opk_pub = bob_opk_pairs[0][1]

    bob_bundle = PreKeyBundle(
        user_id="bob",
        identity_dh_pub=bob_id.dh_pub_bytes,
        identity_sign_pub=bob_id.sign_pub_bytes,
        signed_prekey_pub=bob_spk_pub,
        signed_prekey_sig=bob_spk_sig,
        one_time_prekey_pub=bob_opk_pub,
    )

    alice_master, alice_ek_pub, used_opk = x3dh_initiator(alice_id, bob_bundle)
    assert used_opk == bob_opk_pub

    bob_master = x3dh_receiver(
        bob_identity=bob_id,
        bob_signed_prekey_priv=bob_spk_priv,
        bob_one_time_privs=bob_opk_privs,
        alice_identity_dh_pub=alice_id.dh_pub_bytes,
        alice_ephemeral_pub=alice_ek_pub,
        used_one_time_pub=used_opk,
    )

    assert alice_master == bob_master
    assert len(alice_master) == 32


def test_x3dh_agreement_without_opk() -> None:
    alice_id = IdentityKeyPair("alice")
    bob_id = IdentityKeyPair("bob")

    bob_spk_priv, bob_spk_pub, bob_spk_sig = bob_id.create_signed_prekey()

    bob_bundle = PreKeyBundle(
        user_id="bob",
        identity_dh_pub=bob_id.dh_pub_bytes,
        identity_sign_pub=bob_id.sign_pub_bytes,
        signed_prekey_pub=bob_spk_pub,
        signed_prekey_sig=bob_spk_sig,
        one_time_prekey_pub=None,
    )

    alice_master, alice_ek_pub, used_opk = x3dh_initiator(alice_id, bob_bundle)
    assert used_opk is None

    bob_master = x3dh_receiver(
        bob_identity=bob_id,
        bob_signed_prekey_priv=bob_spk_priv,
        bob_one_time_privs={},
        alice_identity_dh_pub=alice_id.dh_pub_bytes,
        alice_ephemeral_pub=alice_ek_pub,
        used_one_time_pub=None,
    )

    assert alice_master == bob_master


def test_x3dh_invalid_signature_rejected() -> None:
    alice_id = IdentityKeyPair("alice")
    bob_id = IdentityKeyPair("bob")

    _, bob_spk_pub, _ = bob_id.create_signed_prekey()
    fake_sig = b"\x00" * 64

    bad_bundle = PreKeyBundle(
        user_id="bob",
        identity_dh_pub=bob_id.dh_pub_bytes,
        identity_sign_pub=bob_id.sign_pub_bytes,
        signed_prekey_pub=bob_spk_pub,
        signed_prekey_sig=fake_sig,
    )

    with pytest.raises(ValueError, match="Bob's signed prekey signature is invalid"):
        x3dh_initiator(alice_id, bad_bundle)


def test_x3dh_missing_opk_error() -> None:
    alice_id = IdentityKeyPair("alice")
    bob_id = IdentityKeyPair("bob")
    bob_spk_priv, _, _ = bob_id.create_signed_prekey()
    fake_opk_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
    fake_ek_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()

    with pytest.raises(ValueError, match="One-time prekey .* not found"):
        x3dh_receiver(
            bob_identity=bob_id,
            bob_signed_prekey_priv=bob_spk_priv,
            bob_one_time_privs={},
            alice_identity_dh_pub=alice_id.dh_pub_bytes,
            alice_ephemeral_pub=fake_ek_pub,
            used_one_time_pub=fake_opk_pub,
        )


def test_safety_number() -> None:
    id1 = b"\x01" * 32
    id2 = b"\x02" * 32
    sn1 = compute_safety_number(id1, id2)
    sn2 = compute_safety_number(id2, id1)
    assert sn1 == sn2
    assert len(sn1) == 13  # "XXXXXX XXXXXX"
