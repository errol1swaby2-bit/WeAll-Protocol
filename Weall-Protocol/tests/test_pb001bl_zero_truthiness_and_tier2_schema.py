from __future__ import annotations

import copy

import pytest

from weall.runtime.domain_apply import apply_tx_atomic_meta
from weall.runtime.errors import ApplyError
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_schema import validate_tx_envelope
from weall.tx.canon import load_tx_index_json


def _env(tx_type: str, payload: dict, *, signer: str = "alice", nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="sig")


def _user_state() -> dict:
    return {
        "chain_id": "test",
        "height": 10,
        "params": {
            "poh": {
                "tier2_n_jurors": 3,
                "tier2_min_total_reviews": 3,
                "tier2_pass_threshold": 2,
                "tier2_fail_max": 1,
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_expiry_window_blocks": 100,
            }
        },
        "accounts": {
            "alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "reputation": 0,
            }
        },
    }


def test_tier2_request_explicit_zero_target_is_not_coerced_to_tier2() -> None:
    state = _user_state()
    before = copy.deepcopy(state)
    env = _env(
        "POH_TIER2_REQUEST_OPEN",
        {"account_id": "alice", "target_tier": 0, "video_commitment": "cmt:zero-tier"},
    )
    validate_tx_envelope(env.to_json())
    verdict = admit_tx(
        env, state, canon=load_tx_index_json("generated/tx_index.json"), context="mempool"
    )
    assert verdict.ok is True

    with pytest.raises(ApplyError) as raised:
        apply_tx_atomic_meta(state, env)
    assert raised.value.reason == "unsupported_target_tier"
    assert state == before


def test_async_request_explicit_zero_expiry_is_rejected_not_defaulted() -> None:
    state = _user_state()
    before = copy.deepcopy(state)
    env = _env(
        "POH_ASYNC_REQUEST_OPEN",
        {"account_id": "alice", "challenge_id": "challenge-zero", "expires_height": 0},
    )
    validate_tx_envelope(env.to_json())
    verdict = admit_tx(
        env, state, canon=load_tx_index_json("generated/tx_index.json"), context="mempool"
    )
    assert verdict.ok is True

    with pytest.raises(ApplyError) as raised:
        apply_tx_atomic_meta(state, env)
    assert raised.value.reason == "invalid_expiry_height"
    assert state == before


def test_tier2_scheduler_emitted_assignment_passes_block_schema_admission() -> None:
    state = {
        "height": 11,
        "tip": "b" * 64,
        "accounts": {
            "@target": {"poh_tier": 1, "reputation_milli": 0},
            "@j1": {"poh_tier": 2, "reputation_milli": 5000},
            "@j2": {"poh_tier": 2, "reputation_milli": 5000},
            "@j3": {"poh_tier": 2, "reputation_milli": 5000},
        },
        "params": {
            "poh": {
                "tier2_n_jurors": 3,
                "tier2_min_total_reviews": 3,
                "tier2_pass_threshold": 2,
                "tier2_fail_max": 1,
                "tier2_min_rep_milli": 0,
            }
        },
        "roles": {"jurors": {"active_set": ["@j1", "@j2", "@j3"]}},
        "poh": {
            "tier2_cases": {
                "case-1": {
                    "case_id": "case-1",
                    "account_id": "@target",
                    "status": "open",
                    "jurors": {},
                }
            }
        },
    }
    canon = load_tx_index_json("generated/tx_index.json")
    assert schedule_poh_tier2_system_txs(state, next_height=12) == 1
    emitted = system_tx_emitter(state, canon, next_height=12, phase="post")
    assignment = next(env for env in emitted if env.tx_type == "POH_TIER2_JUROR_ASSIGN")

    verdict = admit_tx(assignment, state, canon=canon, context="block")
    assert verdict.ok is True, (verdict.code, verdict.reason, verdict.details)
