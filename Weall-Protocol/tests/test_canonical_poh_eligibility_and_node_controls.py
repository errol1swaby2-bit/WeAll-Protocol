from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.node_operator_responsibilities import evaluate_baseline_node_operator
from weall.runtime.poh.state import set_account_poh_status
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_PAGE = ROOT / "web" / "src" / "pages" / "Account.tsx"


def _env(tx_type: str, signer: str, nonce: int, payload: dict | None = None) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload or {},
        sig="sig",
        parent=None,
        system=False,
    )


def _operator_state(*, legacy_tier: int = 1) -> dict:
    return {
        "height": 10,
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": int(legacy_tier),
                "reputation_milli": 10_000,
                "banned": False,
                "locked": False,
                "devices": {
                    "by_id": {
                        "node:primary": {
                            "device_id": "node:primary",
                            "device_type": "node",
                            "pubkey": "node-pub-1",
                            "revoked": False,
                        }
                    }
                },
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
                        "responsibilities": {},
                    }
                },
            }
        },
    }


def test_canonical_active_tier2_status_grants_operator_responsibility_when_legacy_field_is_stale() -> None:
    state = _operator_state(legacy_tier=1)
    set_account_poh_status(
        state,
        account_id="@op",
        poh_tier=2,
        status="active",
        issuer_authority_id="poh_live_finalize",
        mirror_legacy_account_field=False,
    )

    baseline = evaluate_baseline_node_operator(state, "@op", node_pubkey="node-pub-1")
    assert baseline.active is True
    assert "poh_tier_insufficient" not in baseline.reasons
    assert baseline.details["poh_tier_actual"] == 2

    apply_tx(
        state,
        _env(
            "NODE_OPERATOR_STORAGE_OPT_IN",
            "@op",
            1,
            {
                "account_id": "@op",
                "storage_opt_in": True,
                "declared_capacity_bytes": 1_000_000,
                "node_pubkey": "node-pub-1",
            },
        ),
    )
    storage = state["roles"]["node_operators"]["by_id"]["@op"]["responsibilities"]["storage"]
    assert storage["opted_in"] is True
    assert storage["declared_capacity_bytes"] == 1_000_000


def test_canonical_revocation_blocks_operator_responsibility_even_when_legacy_field_is_tier2() -> None:
    state = _operator_state(legacy_tier=2)
    set_account_poh_status(
        state,
        account_id="@op",
        poh_tier=2,
        status="revoked",
        issuer_authority_id="poh_revoke",
        mirror_legacy_account_field=False,
    )

    baseline = evaluate_baseline_node_operator(state, "@op", node_pubkey="node-pub-1")
    assert baseline.eligible is False
    assert baseline.details["poh_tier_actual"] == 0
    assert "poh_tier_insufficient" in baseline.reasons

    with pytest.raises(ApplyError):
        apply_tx(
            state,
            _env(
                "NODE_OPERATOR_VALIDATOR_OPT_IN",
                "@op",
                1,
                {"account_id": "@op", "validator_opt_in": True, "node_pubkey": "node-pub-1"},
            ),
        )


def test_account_page_surfaces_responsibility_opt_ins_for_existing_registered_node_key() -> None:
    page = ACCOUNT_PAGE.read_text(encoding="utf-8")

    assert "const registeredNodePubkey" in page
    assert "const nodePubkey = generatedNodePubkey || registeredNodePubkey" in page
    assert "Using registered node public key" in page
    assert "registered_node_key_required" in page
    assert "Opt into validator responsibility" in page
    assert "Opt into storage responsibility" in page
