from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
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
    st = {
        "chain_id": "test",
        "height": 7,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 0},
        },
    }
    for i in range(1, 11):
        st["accounts"][f"j{i}"] = {
            "nonce": 0,
            "poh_tier": 3,
            "banned": False,
            "locked": False,
            "reputation": 1,
        }
    return st


def _tier3_payload() -> dict:
    return {
        "account_id": "alice",
        "session_commitment": "session:cmt:1",
        "room_commitment": "room:cmt:1",
        "prompt_commitment": "prompt:cmt:1",
        "device_pairing_commitment": "device:cmt:1",
    }


def _reason(exc: BaseException) -> str:
    return str(getattr(exc, "reason", ""))


def test_legacy_target_tier3_path_is_closed_batch233() -> None:
    st = _state()
    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER2_REQUEST_OPEN",
                {"account_id": "alice", "target_tier": 3},
                signer="alice",
                nonce=1,
            ),
        )
    assert _reason(raised.value) == "tier3_legacy_request_disabled"
    assert not st.get("poh", {}).get("tier3_cases")


def test_tier3_request_requires_session_room_prompt_commitments_batch233() -> None:
    st = _state()
    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER3_REQUEST_OPEN",
                {"account_id": "alice", "room_commitment": "room:cmt:1"},
                signer="alice",
                nonce=1,
            ),
        )
    assert _reason(raised.value) == "missing_tier3_session_commitment"
    assert not st.get("poh", {}).get("tier3_cases")


def test_tier3_init_requires_existing_requested_case_and_matching_session_batch233() -> None:
    st = _state()
    with pytest.raises(ApplyError) as missing:
        apply_tx(
            st,
            _env(
                "POH_TIER3_INIT",
                {"case_id": "poh3:alice:1", "account_id": "alice", "session_commitment": "session:cmt:1"},
                signer="SYSTEM",
                nonce=1,
                system=True,
            ),
        )
    assert _reason(missing.value) == "tier3_case_not_found"

    apply_tx(st, _env("POH_TIER3_REQUEST_OPEN", _tier3_payload(), signer="alice", nonce=1))
    with pytest.raises(ApplyError) as bad_session:
        apply_tx(
            st,
            _env(
                "POH_TIER3_INIT",
                {"case_id": "poh3:alice:1", "account_id": "alice", "session_commitment": "wrong"},
                signer="SYSTEM",
                nonce=2,
                system=True,
            ),
        )
    assert _reason(bad_session.value) == "bad_session_commitment"


def test_tier3_attendance_and_verdict_must_match_session_commitment_batch233() -> None:
    st = _state()
    apply_tx(st, _env("POH_TIER3_REQUEST_OPEN", _tier3_payload(), signer="alice", nonce=1))
    apply_tx(
        st,
        _env(
            "POH_TIER3_INIT",
            {
                "case_id": "poh3:alice:1",
                "account_id": "alice",
                "session_commitment": "session:cmt:1",
                "room_commitment": "room:cmt:1",
                "prompt_commitment": "prompt:cmt:1",
            },
            signer="SYSTEM",
            nonce=2,
            system=True,
        ),
    )
    apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_ASSIGN",
            {"case_id": "poh3:alice:1", "jurors": [f"j{i}" for i in range(1, 11)]},
            signer="SYSTEM",
            nonce=3,
            system=True,
        ),
    )
    apply_tx(st, _env("POH_TIER3_JUROR_ACCEPT", {"case_id": "poh3:alice:1"}, signer="j1", nonce=1))

    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER3_ATTENDANCE_MARK",
                {"case_id": "poh3:alice:1", "juror_id": "j1", "attended": True, "session_commitment": "wrong"},
                signer="j1",
                nonce=2,
            ),
        )
    assert _reason(raised.value) == "bad_session_commitment"

    apply_tx(
        st,
        _env(
            "POH_TIER3_ATTENDANCE_MARK",
            {"case_id": "poh3:alice:1", "juror_id": "j1", "attended": True, "session_commitment": "session:cmt:1"},
            signer="j1",
            nonce=3,
        ),
    )
    with pytest.raises(ApplyError) as verdict_bad:
        apply_tx(
            st,
            _env(
                "POH_TIER3_VERDICT_SUBMIT",
                {"case_id": "poh3:alice:1", "verdict": "pass", "session_commitment": "wrong"},
                signer="j1",
                nonce=4,
            ),
        )
    assert _reason(verdict_bad.value) == "bad_session_commitment"
