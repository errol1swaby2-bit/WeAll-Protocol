from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter, validate_system_tx_queue_binding
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _tx_index() -> TxIndex:
    return TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="",
        system=system,
        parent=parent,
    )


def _state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 10,
        "time": 9_999,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 0,
            },
            "@validator-only": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "balance": 0,
            },
            "SYSTEM": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "balance": 0,
            },
        },
        "roles": {
            "validators": {
                "active_set": ["@validator-only"],
                "by_id": {"@validator-only": {"status": "active", "active": True}},
            }
        },
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 1,
            "economics_enabled": False,
            "gov_action_allowlist": ["ECONOMICS_ACTIVATION"],
        },
        "ballot_profile": {
            "profile_id": "production-review-complete-test-v1",
            "active": True,
        },
        "ballot_profile_activation_receipts": [
            {
                "profile_id": "production-review-complete-test-v1",
                "status": "active",
                "profile_hash": "sha256:test-production-ballot-profile",
                "allowed_modes": ["production"],
                "independent_review_complete": True,
            }
        ],
        "tokenomics_simulation": {
            "cap": 21_000_000,
            "epoch_count": 8,
            "checksum": "sim-v1",
        },
        "treasury_wallets": {
            "public_goods": {
                "account_id": "treasury:public_goods",
                "balance": 0,
            }
        },
        "economics": {
            "fee_policy": {
                "transfer_fee_int": 0,
                "post_fee_int": 0,
                "comment_fee_int": 0,
                "governance_vote_fee_int": 0,
            },
            "wallet_policy": {
                "initialization": "explicit_account_register_or_genesis",
                "recovery": "manual_governance_or_user_key_rotation",
                "pending_failed_read_model": True,
            },
            "reward_policy": {
                "eligible_roles": ["juror", "reviewer", "operator", "validator", "creator"],
                "recipient_eligibility": {
                    "requires_active_poh": True,
                    "no_locked_or_banned_accounts": True,
                },
            },
            "anti_farming_policy": {
                "duplicate_reward_window_blocks": 1000,
                "max_reward_claims_per_epoch": 1,
                "requires_unique_work_id": True,
            },
            "transfer_receipt_policy": {
                "pending_receipts": True,
                "failed_receipts": True,
                "dedupe_by_transfer_id": True,
            },
            "treasury_accountability_policy": {
                "public_report_required": True,
                "spend_receipt_required": True,
                "governance_parent_required": True,
            },
        },
        "system_queue": [],
    }


def test_economics_activation_proposal_uses_verified_humans_not_validator_roles() -> None:
    st = _state()

    out = apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-econ",
                "title": "activate economics",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}],
            },
        ),
    )

    assert out == {"applied": True, "proposal_id": "p-econ"}
    proposal = st["gov_proposals_by_id"]["p-econ"]
    assert proposal["electorate_scope"] == "protocol_tier2"
    assert proposal["electorate_source"] == "protocol_tier2_accounts"
    assert proposal["eligible_voter_ids"] == ["@alice"]
    assert "@validator-only" not in proposal["eligible_voter_ids"]
    assert st["params"]["economics_enabled"] is False


def test_economics_activation_executes_only_after_verified_human_vote_and_readiness() -> None:
    st = _state()
    canon = _tx_index()

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-econ",
                "title": "activate economics",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}],
            },
        ),
    )
    apply_tx(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p-econ", "vote": "yes"}))

    emitted = system_tx_emitter(st, canon, next_height=11, phase="post")
    for env in emitted:
        ok, why = validate_system_tx_queue_binding(st, canon, env, next_height=11, phase="post")
        assert ok, why
        apply_tx(st, env)

    emitted = system_tx_emitter(st, canon, next_height=12, phase="post")
    assert [env.tx_type for env in emitted] == [
        "ECONOMICS_ACTIVATION",
        "GOV_EXECUTION_RECEIPT",
        "GOV_PROPOSAL_RECEIPT",
    ]
    for env in emitted:
        ok, why = validate_system_tx_queue_binding(st, canon, env, next_height=12, phase="post")
        assert ok, why
        apply_tx(st, env)

    assert st["params"]["economics_enabled"] is True
    assert st["economics"]["activation_preconditions"]["ready"] is True
