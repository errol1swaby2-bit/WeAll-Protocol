from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def _state() -> dict:
    return {
        "chain_id": "test",
        "height": 7,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 0},
            "bob": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0},
            "j1": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1},
        },
    }


def _reason(exc: BaseException) -> str:
    return str(getattr(exc, "reason", ""))


def test_tier3_dedicated_request_requires_tier2_subject() -> None:
    st = _state()

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env("POH_TIER3_REQUEST_OPEN", {"account_id": "bob"}, signer="bob", nonce=1),
        )

    assert _reason(raised.value) == "tier3_request_requires_tier2"
    assert "poh" not in st or not st.get("poh", {}).get("tier3_cases")


def test_tier3_dedicated_request_is_subject_owned() -> None:
    st = _state()

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env("POH_TIER3_REQUEST_OPEN", {"account_id": "alice"}, signer="j1", nonce=1),
        )

    assert _reason(raised.value) == "subject_signer_mismatch"
    assert "poh" not in st or not st.get("poh", {}).get("tier3_cases")


def test_tier3_dedicated_request_creates_case_session_and_transport_boundary() -> None:
    st = _state()

    result = apply_tx(
        st,
        _env(
            "POH_TIER3_REQUEST_OPEN",
            {
                "account_id": "alice",
                "room_commitment": "room:cmt:1",
                "prompt_commitment": "prompt:cmt:1",
                "device_pairing_commitment": "device:cmt:1",
            },
            signer="alice",
            nonce=2,
        ),
    )

    assert result and result["applied"] == "POH_TIER3_REQUEST_OPEN"
    assert result["case_id"] == "poh3:alice:2"
    assert result["session_id"] == "session:poh3:alice:2"

    case = st["poh"]["tier3_cases"]["poh3:alice:2"]
    assert case["status"] == "requested"
    assert case["target_tier"] == 3
    assert case["protocol_native"] is True
    assert case["relay_authority"] == "transport_only"
    assert case["room_commitment"] == "room:cmt:1"
    assert case["prompt_commitment"] == "prompt:cmt:1"
    assert case["device_pairing_commitment"] == "device:cmt:1"

    session = st["poh"]["tier3_sessions"]["session:poh3:alice:2"]
    assert session["case_id"] == "poh3:alice:2"
    assert session["relay_authority"] == "transport_only"
    assert "join_url" not in session
    assert st["poh"]["tier3_session_participants"]["session:poh3:alice:2"]["alice"]["role"] == "subject"


def test_tier3_dedicated_request_blocks_duplicate_active_case() -> None:
    st = _state()

    apply_tx(
        st,
        _env("POH_TIER3_REQUEST_OPEN", {"account_id": "alice"}, signer="alice", nonce=1),
    )

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env("POH_TIER3_REQUEST_OPEN", {"account_id": "alice"}, signer="alice", nonce=2),
        )

    assert _reason(raised.value) == "active_tier3_case_exists"


def test_tier3_request_skeleton_uses_dedicated_tx_type() -> None:
    client = TestClient(create_app(boot_runtime=False))

    response = client.post(
        "/v1/poh/tier3/tx/request",
        json={
            "account_id": "alice",
            "room_commitment": "room:cmt:1",
            "prompt_commitment": "prompt:cmt:1",
        },
    )

    assert response.status_code == 200
    tx = response.json()["tx"]
    assert tx["tx_type"] == "POH_TIER3_REQUEST_OPEN"
    assert tx["signer_hint"] == "alice"
    assert tx["payload"] == {
        "account_id": "alice",
        "room_commitment": "room:cmt:1",
        "prompt_commitment": "prompt:cmt:1",
    }
