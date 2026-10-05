from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.apply.poh import _grant_active_poh_tier, apply_poh
from weall.runtime.errors import ApplyError
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.state import (
    POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED,
    poh_human_authority_mode,
    poh_human_authority_scope_closed,
)
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs

ROOT = Path(__file__).resolve().parents[1]


def _env(tx_type: str, *, signer: str = "subject", system: bool = False) -> dict[str, object]:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": 1,
        "sig": "",
        "system": system,
        "payload": {},
    }


def _state(*, closed: bool = True) -> dict[str, object]:
    poh_params: dict[str, object] = {}
    if closed:
        poh_params["human_authority_mode"] = POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED
    return {
        "chain_id": "weall-prod" if closed else "dev-chain",
        "height": 100,
        "tip": "tip",
        "params": {"poh": poh_params},
        "accounts": {
            "subject": {"nonce": 0, "poh_tier": 0, "poh_status": "expired"},
            "primary": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
            "challenger": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
            "reviewer": {"nonce": 0, "poh_tier": 2, "poh_status": "active"},
        },
        "poh": {
            "account_status": {
                "primary": {"account_id": "primary", "poh_tier": 2, "status": "active"},
                "challenger": {"account_id": "challenger", "poh_tier": 2, "status": "active"},
                "reviewer": {"account_id": "reviewer", "poh_tier": 2, "status": "active"},
            },
            "async_cases": {
                "a": {
                    "case_id": "a",
                    "account_id": "subject",
                    "status": "open",
                    "evidence_binds": {"e": {"followup_round": 0}},
                }
            },
            "tier2_cases": {"t": {"case_id": "t", "account_id": "subject", "status": "open"}},
            "live_cases": {
                "l": {
                    "case_id": "l",
                    "account_id": "subject",
                    "status": "requested",
                    "session_commitment": "a" * 64,
                    "room_commitment": "b" * 64,
                    "prompt_commitment": "c" * 64,
                }
            },
        },
        "system_tx_queue": [],
    }


@pytest.mark.parametrize(
    "tx_type",
    [
        "POH_APPLICATION_SUBMIT",
        "POH_ASYNC_REQUEST_OPEN",
        "POH_ASYNC_JUROR_ASSIGN",
        "POH_ASYNC_FINALIZE",
        "POH_TIER_SET",
        "POH_BOOTSTRAP_TIER2_GRANT",
        "POH_TIER2_REQUEST_OPEN",
        "POH_TIER2_JUROR_ASSIGN",
        "POH_TIER2_FINALIZE",
        "POH_LIVE_REQUEST_OPEN",
        "POH_LIVE_JUROR_ASSIGN",
        "POH_LIVE_FINALIZE",
    ],
)
def test_scope_closed_apply_boundary_rejects_positive_human_authority(tx_type: str) -> None:
    state = _state()
    with pytest.raises(ApplyError) as excinfo:
        apply_poh(
            state,
            _env(
                tx_type,
                signer="SYSTEM"
                if "ASSIGN" in tx_type
                or "FINALIZE" in tx_type
                or tx_type in {"POH_TIER_SET", "POH_BOOTSTRAP_TIER2_GRANT"}
                else "subject",
                system=(
                    "ASSIGN" in tx_type
                    or "FINALIZE" in tx_type
                    or tx_type in {"POH_TIER_SET", "POH_BOOTSTRAP_TIER2_GRANT"}
                ),
            ),
        )
    assert excinfo.value.reason == "poh_human_authority_scope_closed"


def test_scope_closed_direct_award_helper_fails_closed() -> None:
    state = _state()
    with pytest.raises(ApplyError) as excinfo:
        _grant_active_poh_tier(state, account_id="subject", tier=2)
    assert excinfo.value.reason == "poh_human_authority_scope_closed"
    assert state["accounts"]["subject"]["poh_tier"] == 0


def test_scope_closed_schedulers_do_not_select_or_enqueue_reviewers() -> None:
    state = _state()
    before = list(state["system_tx_queue"])
    assert schedule_poh_async_system_txs(state, next_height=101) == 0
    assert schedule_poh_tier2_system_txs(state, next_height=101) == 0
    assert schedule_poh_live_system_txs(state, next_height=101) == 0
    assert state["system_tx_queue"] == before


def test_duplicate_challenge_remains_available_for_existing_authority() -> None:
    state = _state()
    env = _env("POH_CHALLENGE_OPEN", signer="challenger")
    env["payload"] = {
        "account_id": "primary",
        "reference_account_id": "reviewer",
        "reason": "duplicate-human-suspected",
    }
    out = apply_poh(state, env)
    assert out and out["applied"] == "POH_CHALLENGE_OPEN"


def test_nonproduction_compatibility_lane_is_not_silently_disabled() -> None:
    state = _state(closed=False)
    assert poh_human_authority_scope_closed(state) is False
    env = _env("POH_APPLICATION_SUBMIT")
    env["payload"] = {"account_id": "subject", "application_id": "dev-app"}
    out = apply_poh(state, env)
    assert out == {"applied": "POH_APPLICATION_SUBMIT", "application_id": "dev-app"}


def test_checked_production_genesis_commits_scope_closed_mode_and_only_bootstrap_tier2() -> None:
    ledger = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    assert poh_human_authority_mode(ledger) == POH_HUMAN_AUTHORITY_MODE_SCOPE_CLOSED
    assert poh_human_authority_scope_closed(ledger) is True
    tier2_accounts = sorted(
        account_id
        for account_id, rec in ledger["accounts"].items()
        if isinstance(rec, dict) and int(rec.get("poh_tier") or 0) >= 2
    )
    assert tier2_accounts == ["@errol-genesis"]
    grant = ledger["poh"]["bootstrap_grants"]["by_id"]
    assert len(grant) == 1
    assert next(iter(grant.values()))["transitional"] is True
