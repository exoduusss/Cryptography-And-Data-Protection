"""FastAPI untrusted relay server for end-to-end encrypted messaging.

Educational reference implementation. The server only sees ciphertext and metadata.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect

from week2_double_ratchet.backend.models import (
    PreKeyBundleResponse,
    RegisterUserRequest,
    RelayMessagePacket,
    ServerStorageLog,
    UploadPreKeysRequest,
)
from week2_double_ratchet.backend.websocket import ConnectionManager


def create_relay_app() -> FastAPI:
    """Create and configure the FastAPI untrusted relay server."""
    app = FastAPI(
        title="Double Ratchet Untrusted Relay Server",
        description="E2EE message switchboard. Zero plaintext or private keys stored.",
        version="0.2.0",
    )

    manager = ConnectionManager()

    # In-memory storage for relay metadata
    users: dict[str, dict[str, str]] = {}
    signed_prekeys: dict[str, dict[str, str]] = {}
    one_time_prekeys: dict[str, list[str]] = {}
    offline_messages: dict[str, list[dict[str, Any]]] = {}
    server_logs: list[ServerStorageLog] = []

    @app.post("/api/register")
    def register_user(req: RegisterUserRequest) -> dict[str, str]:
        users[req.user_id] = {
            "identity_dh_pub": req.identity_dh_pub,
            "identity_sign_pub": req.identity_sign_pub,
        }
        if req.user_id not in offline_messages:
            offline_messages[req.user_id] = []
        return {"status": "registered", "user_id": req.user_id}

    @app.get("/api/users")
    def list_users() -> list[str]:
        return list(users.keys())

    @app.post("/api/prekeys")
    def upload_prekeys(req: UploadPreKeysRequest) -> dict[str, Any]:
        if req.user_id not in users:
            raise HTTPException(status_code=404, detail="User not registered")

        signed_prekeys[req.user_id] = {
            "signed_prekey_pub": req.signed_prekey_pub,
            "signed_prekey_sig": req.signed_prekey_sig,
        }
        if req.user_id not in one_time_prekeys:
            one_time_prekeys[req.user_id] = []
        one_time_prekeys[req.user_id].extend(req.one_time_prekeys)

        return {
            "status": "uploaded",
            "signed_prekey": req.signed_prekey_pub,
            "one_time_prekeys_count": len(one_time_prekeys[req.user_id]),
        }

    @app.get("/api/prekeys/{user_id}", response_model=PreKeyBundleResponse)
    def get_prekey_bundle(user_id: str) -> PreKeyBundleResponse:
        if user_id not in users or user_id not in signed_prekeys:
            raise HTTPException(status_code=404, detail="User prekeys not found")

        u = users[user_id]
        spk = signed_prekeys[user_id]

        opk_pub: str | None = None
        if one_time_prekeys.get(user_id):
            opk_pub = one_time_prekeys[user_id].pop(0)

        return PreKeyBundleResponse(
            user_id=user_id,
            identity_dh_pub=u["identity_dh_pub"],
            identity_sign_pub=u["identity_sign_pub"],
            signed_prekey_pub=spk["signed_prekey_pub"],
            signed_prekey_sig=spk["signed_prekey_sig"],
            one_time_prekey_pub=opk_pub,
        )

    @app.post("/api/send")
    async def send_message(packet: RelayMessagePacket) -> dict[str, str]:
        # Log metadata in server storage log to verify zero-plaintext retention
        ciphertext_hex = packet.payload.get("ciphertext", "")
        log_entry = ServerStorageLog(
            id=len(server_logs) + 1,
            timestamp=time.time(),
            sender_id=packet.sender_id,
            recipient_id=packet.recipient_id,
            message_type=packet.message_type,
            ciphertext_hex=ciphertext_hex[:32] + "...",
            ciphertext_len=len(ciphertext_hex) // 2,
        )
        server_logs.append(log_entry)

        # Dispatch to active websocket or store offline
        delivered = await manager.send_to_user(packet.recipient_id, packet.model_dump())
        if not delivered:
            offline_messages.setdefault(packet.recipient_id, []).append(packet.model_dump())

        return {"status": "dispatched" if delivered else "queued"}

    @app.get("/api/logs")
    def get_server_logs() -> list[ServerStorageLog]:
        return server_logs

    @app.websocket("/ws/{user_id}")
    async def websocket_endpoint(websocket: WebSocket, user_id: str) -> None:
        await manager.connect(user_id, websocket)

        # Flush any offline queued messages
        if user_id in offline_messages and offline_messages[user_id]:
            for msg in offline_messages[user_id]:
                await websocket.send_json(msg)
            offline_messages[user_id].clear()

        try:
            while True:
                data = await websocket.receive_json()
                packet = RelayMessagePacket(**data)

                # Log ciphertext metadata
                ct_hex = packet.payload.get("ciphertext", "")
                server_logs.append(
                    ServerStorageLog(
                        id=len(server_logs) + 1,
                        timestamp=time.time(),
                        sender_id=packet.sender_id,
                        recipient_id=packet.recipient_id,
                        message_type=packet.message_type,
                        ciphertext_hex=ct_hex[:32] + "...",
                        ciphertext_len=len(ct_hex) // 2,
                    )
                )

                # Forward to recipient
                delivered = await manager.send_to_user(packet.recipient_id, packet.model_dump())
                if not delivered:
                    offline_messages.setdefault(packet.recipient_id, []).append(packet.model_dump())

        except WebSocketDisconnect:
            manager.disconnect(user_id)

    return app


app = create_relay_app()
