from __future__ import annotations

import os

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight
from weall.runtime.node_operator_responsibilities import evaluate_node_operator_responsibilities
from weall.runtime.reviewer_responsibilities import reviewer_lane_active
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, payload: dict, *, signer: str, nonce: int = 1, system: bool = False) -> TxEnvelope:
    parent = f"p:{nonce - 1}" if system else None
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="sig", parent=parent, system=system)


def _tier2_account(*, reputation_milli: int = 6000) -> dict:
    return {
        "nonce": 0,
        "poh_tier": 2,
        "banned": False,
        "locked": False,
        "reputation_milli": int(reputation_milli),
        "devices": {
            "by_id": {
                "node:primary": {
                    "device_type": "node",
                    "pubkey": "node-pubkey:primary",
                    "revoked": False,
                }
            }
        },
    }


def _operator_state() -> dict:
    return {
        "height": 10,
        "accounts": {"@op": _tier2_account()},
        "roles": {"node_operators": {"by_id": {}, "active_set": []}, "jurors": {"by_id": {}, "active_set": []}},
    }


def _activate_operator(state: dict, account: str = "@op") -> None:
    apply_tx(state, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": account}, signer=account, nonce=1))
    apply_tx(state, _env("ROLE_NODE_OPERATOR_ACTIVATE", {"account_id": account}, signer="SYSTEM", nonce=2, system=True))


def _preflight(state: dict, *, roles: tuple[str, ...], helper_requested: bool = False, bft_requested: bool = False):
    return evaluate_production_preflight(
        state=state,
        node_id="node-1",
        chain_id="weall-test",
        schema_version="1",
        tx_index_hash="sha256:tx-index",
        runtime_profile_hash="sha256:runtime-profile",
        requested_roles=roles,
        helper_requested=helper_requested,
        bft_requested=bft_requested,
        sigverify_required=True,
        trusted_anchor_required=True,
    )


def test_role_juror_enroll_no_longer_silently_activates_reviewer_lanes() -> None:
    state = {"height": 1, "accounts": {"@reviewer": _tier2_account()}, "roles": {"jurors": {"by_id": {}, "active_set": []}}}

    out = apply_tx(state, _env("ROLE_JUROR_ENROLL", {"account_id": "@reviewer"}, signer="@reviewer", nonce=1))

    assert out["applied"] == "ROLE_JUROR_ENROLL"
    assert out["reviewer_lane_policy"] == "exact_lane_opt_in_required"
    assert out["reviewer_lanes"] == []
    for lane in ("content_review", "dispute_review", "poh_async_review", "poh_live_review"):
        assert reviewer_lane_active(state, "@reviewer", lane) is False


def test_reviewer_lane_opt_in_is_exact_and_withdrawable() -> None:
    state = {"height": 1, "accounts": {"@reviewer": _tier2_account()}, "roles": {"jurors": {"by_id": {}, "active_set": []}}}

    out = apply_tx(
        state,
        _env(
            "REVIEWER_LANE_OPT_IN",
            {"account_id": "@reviewer", "lane": "content_review"},
            signer="@reviewer",
            nonce=1,
        ),
    )

    assert out["applied"] == "REVIEWER_LANE_OPT_IN"
    assert out["lanes"] == ["content_review"]
    assert reviewer_lane_active(state, "@reviewer", "content_review") is True
    assert reviewer_lane_active(state, "@reviewer", "dispute_review") is False
    assert reviewer_lane_active(state, "@reviewer", "poh_async_review") is False
    assert reviewer_lane_active(state, "@reviewer", "poh_live_review") is False

    out = apply_tx(
        state,
        _env(
            "REVIEWER_LANE_OPT_OUT",
            {"account_id": "@reviewer", "lane": "content_review"},
            signer="@reviewer",
            nonce=2,
        ),
    )
    assert out["applied"] == "REVIEWER_LANE_OPT_OUT"
    assert reviewer_lane_active(state, "@reviewer", "content_review") is False


def test_baseline_node_operator_does_not_start_helper_without_helper_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _operator_state()
    _activate_operator(state)
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pubkey:primary")

    evaluation = evaluate_node_operator_responsibilities(state, "@op", node_pubkey="node-pubkey:primary")
    assert evaluation["baseline"]["active"] is True
    assert evaluation["helper"]["status"] == "not_opted_in"

    result = _preflight(state, roles=("helper",), helper_requested=True)
    assert result.helper_effective is False
    assert "helper" not in result.effective_roles
    assert "HELPER_RESPONSIBILITY_NOT_ACTIVE" in result.maintenance_reasons


def test_helper_opt_in_activates_only_helper_service_lane(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _operator_state()
    _activate_operator(state)
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pubkey:primary")

    out = apply_tx(
        state,
        _env(
            "NODE_OPERATOR_HELPER_OPT_IN",
            {
                "account_id": "@op",
                "node_pubkey": "node-pubkey:primary",
                "helper_capacity_units": 4,
                "helper_endpoint_commitment": "sha256:helper-endpoint",
            },
            signer="@op",
            nonce=3,
        ),
    )

    assert out["applied"] == "NODE_OPERATOR_HELPER_OPT_IN"
    evaluation = evaluate_node_operator_responsibilities(state, "@op", node_pubkey="node-pubkey:primary")
    assert evaluation["helper"]["active"] is True
    assert evaluation["validator"]["active"] is False
    assert evaluation["storage"]["active"] is False

    result = _preflight(state, roles=("helper",), helper_requested=True)
    assert result.helper_effective is True
    assert "helper" in result.effective_roles
    assert "validator" not in result.effective_roles
    assert "storage_operator" not in result.effective_roles


def test_storage_declaration_does_not_make_ipfs_pinning_capacity_active(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _operator_state()
    _activate_operator(state)
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pubkey:primary")

    out = apply_tx(
        state,
        _env(
            "NODE_OPERATOR_STORAGE_OPT_IN",
            {"account_id": "@op", "node_pubkey": "node-pubkey:primary", "declared_capacity_bytes": 1000},
            signer="@op",
            nonce=3,
        ),
    )
    assert out["applied"] == "NODE_OPERATOR_STORAGE_OPT_IN"

    evaluation = evaluate_node_operator_responsibilities(state, "@op", node_pubkey="node-pubkey:primary")
    assert evaluation["storage"]["status"] == "proof_pending"
    assert evaluation["storage"]["active"] is False
    assert "capacity_proof_pending" in evaluation["storage"]["reasons"]

    result = _preflight(state, roles=("storage_operator",), helper_requested=False)
    assert "storage_operator" not in result.effective_roles
    assert "ROLE_NOT_ACTIVE" in result.maintenance_reasons


def test_foreign_account_cannot_update_helper_or_reviewer_lane() -> None:
    state = _operator_state()
    state["accounts"]["@attacker"] = _tier2_account()
    _activate_operator(state)

    with pytest.raises(ApplyError) as helper_exc:
        apply_tx(
            state,
            _env("NODE_OPERATOR_HELPER_OPT_IN", {"account_id": "@op"}, signer="@attacker", nonce=3),
        )
    assert helper_exc.value.reason == "only_account_can_update_helper_responsibility"

    with pytest.raises(ApplyError) as lane_exc:
        apply_tx(
            state,
            _env("REVIEWER_LANE_OPT_IN", {"account_id": "@op", "lane": "content_review"}, signer="@attacker", nonce=4),
        )
    assert lane_exc.value.reason == "only_account_can_update_reviewer_lane"
