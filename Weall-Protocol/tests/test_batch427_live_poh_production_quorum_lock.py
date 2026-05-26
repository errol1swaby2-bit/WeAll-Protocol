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
    *,
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


def _state(*, production: bool) -> dict:
    accounts = {
        "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation_milli": 0}
    }
    for i in range(1, 6):
        accounts[f"j{i}"] = {
            "nonce": 0,
            "poh_tier": 2,
            "banned": False,
            "locked": False,
            "reputation_milli": 5000,
        }

    poh_params = {"live_min_rep_milli": 0}
    if production:
        poh_params["live_poh_policy_mode"] = "production"

    return {
        "chain_id": "test",
        "height": 1,
        "tip": "d" * 64,
        "accounts": accounts,
        "params": {"poh": poh_params},
    }


def _open_case(st: dict) -> str:
    m0 = apply_tx(
        st,
        _env(
            "POH_LIVE_REQUEST_OPEN",
            {
                "account_id": "alice",
                "session_commitment": "sc:1",
                "room_commitment": "room:1",
                "prompt_commitment": "prompt:1",
            },
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(m0["case_id"])
    apply_tx(
        st,
        _env(
            "POH_LIVE_SESSION_INIT",
            {"case_id": case_id, "account_id": "alice", "session_commitment": "sc:1", "ts_ms": 1},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_LIVE_REQUEST_OPEN",
        ),
    )
    return case_id


def _assign(st: dict, case_id: str, jurors: list[str]) -> dict:
    m = apply_tx(
        st,
        _env(
            "POH_LIVE_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": jurors},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_LIVE_SESSION_INIT",
        ),
    )
    return dict(m["live_quorum"])


def _active_vote(st: dict, case_id: str, juror_id: str, verdict: str, nonce: int) -> int:
    apply_tx(st, _env("POH_LIVE_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": nonce}, signer=juror_id, nonce=nonce))
    nonce += 1
    apply_tx(
        st,
        _env(
            "POH_LIVE_ATTENDANCE_MARK",
            {"case_id": case_id, "juror_id": juror_id, "attended": True, "session_commitment": "sc:1", "ts_ms": nonce},
            signer=juror_id,
            nonce=nonce,
        ),
    )
    nonce += 1
    apply_tx(
        st,
        _env(
            "POH_LIVE_VERDICT_SUBMIT",
            {"case_id": case_id, "verdict": verdict, "session_commitment": "sc:1", "ts_ms": nonce},
            signer=juror_id,
            nonce=nonce,
        ),
    )
    return nonce + 1


def _finalize(st: dict, case_id: str, nonce: int) -> dict:
    return dict(
        apply_tx(
            st,
            _env(
                "POH_LIVE_FINALIZE",
                {"case_id": case_id, "ts_ms": nonce},
                signer="SYSTEM",
                nonce=nonce,
                system=True,
                parent="POH_LIVE_VERDICT_SUBMIT",
            ),
        )
    )


def test_bootstrap_mode_still_allows_one_juror_live_quorum() -> None:
    st = _state(production=False)
    case_id = _open_case(st)
    quorum = _assign(st, case_id, ["j1"])

    assert quorum["mode"] == "bootstrap"
    assert quorum["juror_count"] == 1
    assert quorum["required_passes"] == 1


def test_production_mode_rejects_one_juror_assignment() -> None:
    st = _state(production=True)
    case_id = _open_case(st)

    with pytest.raises(ApplyError) as ei:
        _assign(st, case_id, ["j1"])

    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "live_production_panel_size_required"


def test_production_mode_requires_three_approvals_from_fixed_panel() -> None:
    st = _state(production=True)
    case_id = _open_case(st)
    quorum = _assign(st, case_id, ["j1", "j2", "j3", "j4", "j5"])

    assert quorum["mode"] == "production"
    assert quorum["juror_count"] == 5
    assert quorum["active_reviewers"] == 3
    assert quorum["required_verdicts"] == 3
    assert quorum["required_passes"] == 3

    nonce = 4
    nonce = _active_vote(st, case_id, "j1", "pass", nonce)
    nonce = _active_vote(st, case_id, "j2", "pass", nonce)
    nonce = _active_vote(st, case_id, "j3", "fail", nonce)
    final = _finalize(st, case_id, nonce)

    assert final["outcome"] == "fail"
    assert final["tier_awarded"] == 0
    assert final["live_quorum"]["actual_passes"] == 2


def test_production_mode_awards_tier2_only_after_three_passes() -> None:
    st = _state(production=True)
    case_id = _open_case(st)
    _assign(st, case_id, ["j1", "j2", "j3", "j4", "j5"])

    nonce = 4
    nonce = _active_vote(st, case_id, "j1", "pass", nonce)
    nonce = _active_vote(st, case_id, "j2", "pass", nonce)
    nonce = _active_vote(st, case_id, "j3", "pass", nonce)
    final = _finalize(st, case_id, nonce)

    assert final["outcome"] == "pass"
    assert final["tier_awarded"] == 2
    assert st["accounts"]["alice"]["poh_tier"] == 2
    assert final["live_quorum"]["mode"] == "production"
