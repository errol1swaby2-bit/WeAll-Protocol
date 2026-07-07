from __future__ import annotations

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.block_admission import admit_block_txs
from weall.tx.canon import TxIndex


def _env(tx_type: str, payload: dict, *, signer: str = "SYSTEM", nonce: int = 1, system: bool = True) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent="parent:0" if system else None,
        system=system,
    )


def _state() -> dict:
    return {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 999999999999, "economics_enabled": False},
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
            "@bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
            "SYSTEM": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
        },
        "system_queue": [],
    }


def test_rate_limit_policy_is_bounded_and_canonical_even_during_economics_lock() -> None:
    state = _state()

    result = apply_economics(
        state,
        _env(
            "RATE_LIMIT_POLICY_SET",
            {
                "scope": "tx_submit",
                "window_ms": 60_000,
                "limit": 120,
                "policy": {
                    "account_register": {"window_ms": 60_000, "limit": 20},
                    "relay": {"window_ms": 10_000, "limit": 50},
                },
            },
        ),
    )

    assert result["applied"] == "RATE_LIMIT_POLICY_SET"
    assert state["economics"]["rate_limit_policy"] == {
        "version": 1,
        "rules": {
            "account_onboarding": {"window_ms": 60_000, "limit": 20},
            "relay": {"window_ms": 10_000, "limit": 50},
            "tx_submit": {"window_ms": 60_000, "limit": 120},
        },
    }


def test_rate_limit_policy_rejects_arbitrary_capture_blob_fields() -> None:
    state = _state()

    with pytest.raises(EconomicsApplyError) as excinfo:
        apply_economics(
            state,
            _env(
                "RATE_LIMIT_POLICY_SET",
                {"scope": "global", "window_ms": 60_000, "limit": 100, "deny_all": True},
            ),
        )

    assert excinfo.value.reason == "rate_limit_policy_field_not_allowed"
    assert state.get("economics", {}).get("rate_limit_policy") in (None, {})


def test_rate_limit_policy_rejects_unknown_scopes() -> None:
    state = _state()

    with pytest.raises(EconomicsApplyError) as excinfo:
        apply_economics(
            state,
            _env("RATE_LIMIT_POLICY_SET", {"scope": "specific_user_@alice", "window_ms": 60_000, "limit": 100}),
        )

    assert excinfo.value.reason == "rate_limit_scope_not_allowed"


def test_rate_limit_policy_rejects_zero_and_out_of_bounds_limits() -> None:
    state = _state()

    with pytest.raises(EconomicsApplyError) as excinfo:
        apply_economics(state, _env("RATE_LIMIT_POLICY_SET", {"window_ms": 60_000, "limit": 0}))

    assert excinfo.value.reason == "rate_limit_limit_out_of_bounds"

    with pytest.raises(EconomicsApplyError) as excinfo2:
        apply_economics(state, _env("RATE_LIMIT_POLICY_SET", {"window_ms": 999, "limit": 10}))

    assert excinfo2.value.reason == "rate_limit_window_ms_out_of_bounds"


def test_rate_limit_policy_cannot_choke_protected_onboarding_scopes() -> None:
    state = _state()

    with pytest.raises(EconomicsApplyError) as excinfo:
        apply_economics(
            state,
            _env("RATE_LIMIT_POLICY_SET", {"scope": "account_register", "window_ms": 3_600_000, "limit": 1}),
        )

    assert excinfo.value.reason == "rate_limit_protected_onboarding_scope_too_restrictive"
    assert state.get("economics", {}).get("rate_limit_policy") in (None, {})


def test_rate_limit_strike_requires_existing_target_account() -> None:
    state = _state()

    with pytest.raises(EconomicsApplyError) as excinfo:
        apply_economics(state, _env("RATE_LIMIT_STRIKE_APPLY", {"target": "@ghost", "reason": "spam"}))

    assert excinfo.value.reason == "target_account_missing"
    assert state.get("economics", {}).get("rate_limit_strikes") in (None, [])

    result = apply_economics(state, _env("RATE_LIMIT_STRIKE_APPLY", {"target": "@alice", "reason": "spam"}))
    assert result == {"applied": "RATE_LIMIT_STRIKE_APPLY", "target": "@alice"}
    assert state["economics"]["rate_limit_strikes"][0]["target"] == "@alice"


def test_rate_limit_policy_set_is_governance_allowlisted_but_payload_validated() -> None:
    state = _state()
    state["params"]["gov_action_allowlist"] = ["RATE_LIMIT_POLICY_SET"]

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            TxEnvelope(
                tx_type="GOV_PROPOSAL_CREATE",
                signer="@alice",
                nonce=1,
                payload={
                    "proposal_id": "p-rate-bad",
                    "title": "bad rate policy",
                    "actions": [
                        {"tx_type": "RATE_LIMIT_POLICY_SET", "payload": {"scope": "account_register", "window_ms": 3_600_000, "limit": 1}}
                    ],
                },
                sig="sig",
                system=False,
            ),
        )

    assert excinfo.value.reason == "governance_action_payload_invalid"

    apply_tx(
        state,
        TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="@alice",
            nonce=2,
            payload={
                "proposal_id": "p-rate-ok",
                "title": "safe rate policy",
                "actions": [
                    {"tx_type": "RATE_LIMIT_POLICY_SET", "payload": {"scope": "account_register", "window_ms": 60_000, "limit": 20}}
                ],
            },
            sig="sig",
            system=False,
        ),
    )

    assert "p-rate-ok" in state["gov_proposals_by_id"]


def test_rate_limit_policy_schema_rejects_zero_in_block_admission() -> None:
    idx = TxIndex.load_from_file("generated/tx_index.json")
    state = _state()
    env = _env("RATE_LIMIT_POLICY_SET", {"window_ms": 60_000, "limit": 0}, nonce=0)

    ledger = LedgerView.from_ledger(state)
    ok, block_reject, per_tx = admit_block_txs([env], ledger, idx, verify_signatures=True)

    assert block_reject is None
    assert per_tx[0] is not None
    assert per_tx[0].code == "invalid_payload"
    assert per_tx[0].reason == "schema_validation_failed"
