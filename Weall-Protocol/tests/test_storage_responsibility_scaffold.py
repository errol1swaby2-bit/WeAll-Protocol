from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_PAGE = ROOT.parent / "web" / "src" / "pages" / "Account.tsx"
QUICKSTART = ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md"
SMOKE = ROOT / "scripts" / "operator_onboarding_smoke.sh"


def _env(tx_type: str, payload: dict, *, signer: str = "@op", system: bool = False, nonce: int = 1) -> dict:
    return {"tx_type": tx_type, "signer": signer, "nonce": nonce, "payload": payload, "sig": "", "system": system}


def _state(*, tier: int = 2, active: bool = True, banned: bool = False, locked: bool = False) -> dict:
    return {
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": int(tier),
                "reputation_milli": 1500,
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
        requested_roles=("storage_operator",),
        helper_requested=False,
        bft_requested=False,
        sigverify_required=True,
        trusted_anchor_required=True,
    )


def test_active_node_operator_can_declare_storage_capacity_but_not_prove_it(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)
    st = _state(tier=2, active=True)

    result = apply_tx(
        st,
        _env(
            "ROLE_NODE_OPERATOR_ENROLL",
            {
                "account_id": "@op",
                "storage_opt_in": True,
                "declared_capacity_bytes": 500_000_000,
                "node_pubkey": "node-pub",
                "storage_endpoint_commitment": "sha256:endpoint",
            },
        ),
    )
    assert result["storage_opted_in"] is True
    storage = st["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]
    assert storage["opted_in"] is True
    assert storage["active"] is False
    assert storage["declared_capacity_bytes"] == 500_000_000
    assert storage["proven_capacity_bytes"] == 0
    assert storage["allocated_capacity_bytes"] == 0
    assert storage["proof_status"] == "probe_pending"
    assert storage["storage_endpoint_commitment"] == "sha256:endpoint"

    preflight = _preflight(st)
    assert not preflight.passed
    assert "ROLE_NOT_ACTIVE" in preflight.maintenance_reasons
    assert "storage_operator" not in preflight.effective_roles


def test_storage_opt_in_requires_active_node_operator_tier2_and_registered_node_key() -> None:
    inactive = _state(tier=2, active=False)
    with pytest.raises(Exception) as exc1:
        apply_tx(inactive, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@op", "storage_opt_in": True, "declared_capacity_bytes": 1}))
    assert "node_operator_status_required" in str(exc1.value)

    tier1 = _state(tier=1, active=True)
    with pytest.raises(Exception) as exc2:
        apply_tx(tier1, _env("ROLE_NODE_OPERATOR_ENROLL", {"account_id": "@op", "storage_opt_in": True, "declared_capacity_bytes": 1}))
    assert "live_verification_required" in str(exc2.value)

    wrong_key = _state(tier=2, active=True)
    with pytest.raises(Exception) as exc3:
        apply_tx(
            wrong_key,
            _env(
                "ROLE_NODE_OPERATOR_ENROLL",
                {"account_id": "@op", "storage_opt_in": True, "declared_capacity_bytes": 1, "node_pubkey": "other"},
            ),
        )
    assert "node_key_not_registered" in str(exc3.value)


def test_proven_capacity_is_the_allocation_boundary(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)
    st = _state(tier=2, active=True)
    rec = st["roles"]["node_operators"]["by_id"]["@op"]
    rec["responsibilities"] = {
        "storage": {
            "opted_in": True,
            "active": True,
            "declared_capacity_bytes": 1_000_000_000,
            "proven_capacity_bytes": 0,
            "allocated_capacity_bytes": 0,
            "proof_status": "probe_pending",
        }
    }
    assert not _preflight(st).passed

    proven = json.loads(json.dumps(st))
    proven["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]["proven_capacity_bytes"] = 1_000_000_000
    proven["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]["proof_status"] = "verified"
    proven["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]["proof_expires_height"] = 100
    result = _preflight(proven)
    assert result.passed
    assert result.effective_roles == ("general_service", "storage_operator")


def test_frontend_and_docs_explain_storage_proof_pending_scaffold() -> None:
    page = ACCOUNT_PAGE.read_text(encoding="utf-8")
    doc = QUICKSTART.read_text(encoding="utf-8")
    smoke = SMOKE.read_text(encoding="utf-8")

    assert "Storage Responsibility" in page
    assert "Opt into storage responsibility" in page
    assert "Declared capacity is not allocation authority" in page
    assert "Blocked until proof" in page
    assert "storage_opt_in" in page
    assert "proven_capacity_bytes" in page

    assert "Declared capacity is not proven capacity" in doc
    assert "Proof pending is not allocation eligible" in doc
    assert "proven_capacity_bytes" in doc
    assert "Opt into storage responsibility" in smoke
