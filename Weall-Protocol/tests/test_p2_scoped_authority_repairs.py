from __future__ import annotations

import pytest

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury
from weall.runtime.node_operator_responsibilities import evaluate_helper_responsibility
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, payload: dict, *, nonce: int = 1, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=system,
        parent="gov:p2" if system else None,
    )


def _helper_state(reputation: int) -> dict:
    return {
        "height": 1,
        "accounts": {
            "@op": {
                "poh_tier": 2,
                "reputation_milli": reputation,
                "banned": False,
                "locked": False,
            }
        },
        "roles": {
            "node_operators": {
                "active_set": ["@op"],
                "by_id": {
                    "@op": {
                        "account_id": "@op",
                        "enrolled": True,
                        "active": True,
                        "status": "active",
                        "responsibilities": {},
                    }
                },
            }
        },
    }


def test_p2_role002_applicant_cannot_lower_helper_reputation_threshold() -> None:
    state = _helper_state(1999)
    with pytest.raises(RolesApplyError) as ei:
        apply_roles(
            state,
            _env(
                "NODE_OPERATOR_HELPER_OPT_IN",
                "@op",
                {"account_id": "@op", "reputation_required_milli": 0},
            ),
        )
    assert ei.value.reason == "helper_reputation_threshold_policy_mismatch"

    with pytest.raises(RolesApplyError) as ei2:
        apply_roles(state, _env("NODE_OPERATOR_HELPER_OPT_IN", "@op", {"account_id": "@op"}))
    assert ei2.value.reason == "helper_reputation_insufficient"


def test_p2_role002_evaluator_ignores_persisted_self_selected_threshold() -> None:
    state = _helper_state(1999)
    state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"] = {
        "helper": {
            "opted_in": True,
            "active": True,
            "reputation_required_milli": 0,
        }
    }
    result = evaluate_helper_responsibility(state, "@op")
    assert result.eligible is False
    assert "helper_reputation_insufficient" in result.reasons
    assert result.details["reputation_required_milli"] == 2000


def test_p2_role002_canonical_minimum_allows_helper_opt_in() -> None:
    state = _helper_state(2000)
    result = apply_roles(state, _env("NODE_OPERATOR_HELPER_OPT_IN", "@op", {"account_id": "@op"}))
    assert result["applied"] == "NODE_OPERATOR_HELPER_OPT_IN"
    helper = state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["helper"]
    assert helper["reputation_required_milli"] == 2000


def _treasury_state(*, signers: list[str], threshold: int = 1) -> dict:
    return {
        "treasury_wallets": {"T": {"wallet_id": "T", "balance": 100, "signers": list(signers)}},
        "roles": {
            "treasuries_by_id": {
                "T": {"signers": list(signers), "threshold": threshold, "require_emissary_signers": False}
            }
        },
    }


def test_p2_treas002_add_remove_updates_canonical_authority_and_wallet_mirror() -> None:
    state = _treasury_state(signers=["@a"], threshold=1)
    add = apply_treasury(
        state,
        _env("TREASURY_SIGNER_ADD", "SYSTEM", {"wallet_id": "T", "signer": "@b"}, system=True),
    )
    assert add["deduped"] is False
    assert state["roles"]["treasuries_by_id"]["T"]["signers"] == ["@a", "@b"]
    assert state["treasury_wallets"]["T"]["signers"] == ["@a", "@b"]

    remove = apply_treasury(
        state,
        _env(
            "TREASURY_SIGNER_REMOVE",
            "SYSTEM",
            {"wallet_id": "T", "signer": "@a"},
            nonce=2,
            system=True,
        ),
    )
    assert remove["deduped"] is False
    assert state["roles"]["treasuries_by_id"]["T"]["signers"] == ["@b"]
    assert state["treasury_wallets"]["T"]["signers"] == ["@b"]


def test_p2_treas002_remove_cannot_make_threshold_impossible() -> None:
    state = _treasury_state(signers=["@a", "@b"], threshold=2)
    with pytest.raises(TreasuryApplyError) as ei:
        apply_treasury(
            state,
            _env("TREASURY_SIGNER_REMOVE", "SYSTEM", {"wallet_id": "T", "signer": "@a"}, system=True),
        )
    assert ei.value.reason == "signer_removal_would_break_threshold"
    assert state["roles"]["treasuries_by_id"]["T"]["signers"] == ["@a", "@b"]


def test_p2_group002_audit_anchor_is_validated_and_bound_to_group_treasury() -> None:
    state = {
        "groups": {"G": {"group_id": "G", "treasury_id": "GT:G"}},
    }
    result = apply_groups(
        state,
        _env(
            "GROUP_TREASURY_AUDIT_ANCHOR_SET",
            "SYSTEM",
            {"group_id": "G", "anchor": {"root": "sha256:abc"}},
            system=True,
        ),
    )
    assert result["treasury_id"] == "GT:G"
    record = state["groups"]["G"]["treasury_audit_anchors"][0]
    assert record["group_id"] == "G"
    assert record["treasury_id"] == "GT:G"
    assert record["anchor"] == {"root": "sha256:abc"}


def test_p2_group002_missing_anchor_fails_without_mutation() -> None:
    state = {"groups": {"G": {"group_id": "G", "treasury_id": "GT:G"}}}
    with pytest.raises(GroupsApplyError) as ei:
        apply_groups(
            state,
            _env(
                "GROUP_TREASURY_AUDIT_ANCHOR_SET",
                "SYSTEM",
                {"group_id": "G"},
                system=True,
            ),
        )
    assert ei.value.reason == "missing_anchor"
    assert "treasury_audit_anchors" not in state["groups"]["G"]
