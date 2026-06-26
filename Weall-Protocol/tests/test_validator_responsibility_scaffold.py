from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_PAGE = ROOT.parent / "web" / "src" / "pages" / "Account.tsx"
QUICKSTART = ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md"
SMOKE = ROOT / "scripts" / "operator_onboarding_smoke.sh"
FRESH_DEMO = ROOT / "scripts" / "fresh_node_operator_candidate_demo.sh"


def _env(tx_type: str, payload: dict, *, signer: str = "@op", system: bool = False, nonce: int = 1) -> dict:
    return {"tx_type": tx_type, "signer": signer, "nonce": nonce, "payload": payload, "sig": "", "system": system}


def _state(*, tier: int = 2, rep: int = 6000, active: bool = True, banned: bool = False, locked: bool = False) -> dict:
    return {
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": int(tier),
                "reputation_milli": int(rep),
                "banned": bool(banned),
                "locked": bool(locked),
                "devices": {
                    "by_id": {
                        "node:primary": {
                            "device_type": "node",
                            "pubkey": "node-pub",
                            "revoked": False,
                        }
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "by_id": {"@op": {"account_id": "@op", "enrolled": True, "active": bool(active)}},
                "active_set": ["@op"] if active else [],
            }
        },
    }


def _preflight(state: dict):
    return evaluate_production_preflight(
        state=state,
        node_id="node-1",
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="txhash",
        runtime_profile_hash="profilehash",
        requested_roles=("validator",),
        helper_requested=False,
        bft_requested=True,
        sigverify_required=True,
        trusted_anchor_required=True,
    )


def test_active_node_operator_can_opt_into_validator_but_not_gain_consensus(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)
    st = _state(tier=2, rep=6000, active=True)

    result = apply_tx(
        st,
        _env(
            "ROLE_NODE_OPERATOR_ENROLL",
            {
                "account_id": "@op",
                "validator_opt_in": True,
                "node_pubkey": "node-pub",
                "validator_readiness_commitment": "sha256:readiness",
            },
        ),
    )
    assert result["validator_opted_in"] is True
    validator = st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["validator"]
    assert validator["opted_in"] is True
    assert validator["active"] is False
    assert validator["readiness_status"] == "pending"
    assert validator["reputation_required_milli"] == 5000
    assert validator["reputation_actual_milli"] == 6000
    assert validator["validator_readiness_commitment"] == "sha256:readiness"

    preflight = _preflight(st)
    assert not preflight.passed
    assert "ROLE_NOT_ACTIVE" in preflight.maintenance_reasons
    assert "validator" not in preflight.effective_roles


def test_validator_opt_in_requires_active_node_operator_tier2_reputation_and_node_key() -> None:
    inactive = _state(tier=2, rep=6000, active=False)
    with pytest.raises(Exception) as exc1:
        apply_tx(inactive, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@op", "validator_opt_in": True}))
    assert "node_operator_status_required" in str(exc1.value)

    tier1 = _state(tier=1, rep=6000, active=True)
    with pytest.raises(Exception) as exc2:
        apply_tx(tier1, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@op", "validator_opt_in": True}))
    assert "live_verification_required" in str(exc2.value)

    low_rep = _state(tier=2, rep=4999, active=True)
    with pytest.raises(Exception) as exc3:
        apply_tx(low_rep, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@op", "validator_opt_in": True}))
    assert "validator_reputation_insufficient" in str(exc3.value)

    wrong_key = _state(tier=2, rep=6000, active=True)
    with pytest.raises(Exception) as exc4:
        apply_tx(
            wrong_key,
            _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@op", "validator_opt_in": True, "node_pubkey": "other"}),
        )
    assert "node_key_not_registered" in str(exc4.value)


def test_validator_readiness_active_is_the_consensus_boundary(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)
    st = _state(tier=2, rep=6000, active=True)
    rec = st["roles"]["node_operators"]["by_id"]["@op"]
    rec["responsibilities"] = {
        "validator": {
            "opted_in": True,
            "active": False,
            "readiness_status": "pending",
            "reputation_required_milli": 5000,
        }
    }
    assert not _preflight(st).passed

    rec["responsibilities"]["validator"]["active"] = True
    rec["responsibilities"]["validator"]["readiness_status"] = "ready"
    result = _preflight(st)
    assert result.passed
    assert result.bft_effective is True
    assert result.effective_roles == ("general_service", "validator")


def test_frontend_docs_and_smoke_explain_validator_responsibility_scaffold() -> None:
    page = ACCOUNT_PAGE.read_text(encoding="utf-8")
    doc = QUICKSTART.read_text(encoding="utf-8")
    smoke = SMOKE.read_text(encoding="utf-8")
    fresh = FRESH_DEMO.read_text(encoding="utf-8")

    assert "Validator Responsibility" in page
    assert "Opt into validator responsibility" in page
    assert "Baseline Node Operator status does not grant validator authority" in page
    assert "Validator readiness and reputation checks" in page
    assert "Blocked until readiness" in page
    assert "validator_opt_in" in page
    assert "validator_readiness_commitment" in page

    assert "Baseline Node Operator status does not grant validator authority" in doc
    assert "Validator readiness and reputation checks must pass before consensus authority" in doc
    assert "Validator responsibility requires explicit opt-in" in doc

    assert "Opt into validator responsibility" in smoke
    assert "Opt into validator responsibility" in fresh
