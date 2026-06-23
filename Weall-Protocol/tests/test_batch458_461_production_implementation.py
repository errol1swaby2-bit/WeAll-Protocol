from __future__ import annotations

from pathlib import Path

from weall.api.routes_public_parts.economics import (
    economics_activation_readiness_from_state,
    transfer_preview_from_state,
    treasury_status_from_state,
)

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def _read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def test_economics_activation_preview_and_treasury_status_batch458_461() -> None:
    st = {
        "height": 0,
        "params": {"economics_enabled": False, "economic_unlock_height": 90},
        "accounts": {"@alice": {"balance": 100}, "@bob": {"balance": 0}},
        "economics": {"fee_policy": {"post_fee_int": 0, "governance_vote_fee_int": 0}},
        "treasury": {"programs": {}, "spends": {}},
        "treasury_wallets": {"main": {"balance": 0}},
    }
    activation = economics_activation_readiness_from_state(st)
    assert activation["ok"] is True
    assert activation["enabled"] is False
    assert any(item["key"] == "civic_fee_floor" for item in activation["requirements"])

    preview = transfer_preview_from_state(st, from_account="@alice", to_account="@bob", amount=5)
    assert preview["allowed"] is False
    assert "economics_locked" in preview["issues"]

    treasury = treasury_status_from_state(st)
    assert treasury["locked"] is True
    assert treasury["wallets"]["main"]["balance"] == 0


def test_block_production_proof_endpoint_and_local_gate_batch458_461() -> None:
    consensus = _read("Weall-Protocol/src/weall/api/routes_public_parts/consensus.py")
    script = _read("Weall-Protocol/scripts/production_block_production_rehearsal_gate.py")
    doc = _read("Weall-Protocol/docs/BLOCK_PRODUCTION_PROOF_GATE.md")

    assert '@router.get("/consensus/block-production/proof")' in consensus
    assert "block_production_proof_from_state" in consensus
    assert "state_root" in consensus and "receipts_root" in consensus and "block_hash" in consensus
    assert "production_block_production_rehearsal_gate" in script or "local production-profile block proof" in script
    assert "public multi-validator BFT not claimed" in doc


def test_e2ee_device_backup_removed_and_live_room_turn_surfaces_remain_batch458_461() -> None:
    crypto = _read("web/src/lib/messageCrypto.ts")
    messaging = _read("web/src/pages/Messaging.tsx")
    webrtc = _read("web/src/lib/webrtcLiveRoom.ts")
    live = _read("web/src/pages/LiveVerificationRoom.tsx")

    assert "exportMessagingIdentityBackup" in crypto
    assert "importMessagingIdentityBackup" in crypto
    assert "revokeLocalMessagingDevice" in crypto
    assert "PBKDF2-SHA256" not in crypto
    assert "Device key lifecycle" not in messaging
    assert "PRIVATE_MESSAGING_UNSUPPORTED" in messaging
    assert "iceServerDiagnostics" in webrtc
    assert "weall.p2p.iceServersJson" in webrtc
    assert "TURN / relay config" in live
    assert "setInterval" in live and "pollWebRTCSignals" in live
