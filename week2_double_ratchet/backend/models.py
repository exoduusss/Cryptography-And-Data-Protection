"""Pydantic data models for untrusted relay server API and WebSocket messages.

Educational reference implementation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RegisterUserRequest(BaseModel):
    user_id: str = Field(..., description="Unique username / client identifier")
    identity_dh_pub: str = Field(..., description="Hex-encoded X25519 public identity key")
    identity_sign_pub: str = Field(
        ..., description="Hex-encoded Ed25519 public signing identity key"
    )


class UploadPreKeysRequest(BaseModel):
    user_id: str
    signed_prekey_pub: str = Field(..., description="Hex-encoded signed prekey")
    signed_prekey_sig: str = Field(..., description="Hex-encoded signature over signed prekey")
    one_time_prekeys: list[str] = Field(
        default_factory=list, description="List of hex-encoded one-time prekeys"
    )


class PreKeyBundleResponse(BaseModel):
    user_id: str
    identity_dh_pub: str
    identity_sign_pub: str
    signed_prekey_pub: str
    signed_prekey_sig: str
    one_time_prekey_pub: str | None = None


class RelayMessagePacket(BaseModel):
    sender_id: str
    recipient_id: str
    message_type: str = Field("chat", description="'chat' or 'note'")
    payload: dict[str, Any] = Field(..., description="Encrypted RatchetMessage dictionary")


class ServerStorageLog(BaseModel):
    id: int
    timestamp: float
    sender_id: str
    recipient_id: str
    message_type: str
    ciphertext_hex: str
    ciphertext_len: int
