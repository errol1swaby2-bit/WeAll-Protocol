from __future__ import annotations

import copy

from p0_assurance import property_cases, property_reproducer
from weall.runtime.account_registration_work import (
    ACCOUNT_REGISTRATION_WORK_VERSION,
    account_registration_work_digest,
    leading_zero_bits,
    verify_account_registration_work,
)
from weall.runtime.block_history import (
    BLOCK_HISTORY_CHECKPOINT_KEY,
    project_bounded_block_history_state,
)
from weall.runtime.poh.juror_select import eligible_live_jurors, pick_async_jurors
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission_types import TxEnvelope


def _permute(value, rng):
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {key: _permute(item, rng) for key, item in items}
    if isinstance(value, list):
        return [_permute(item, rng) for item in value]
    return copy.deepcopy(value)


def _reviewer_state(order: list[str] | None = None) -> dict:
    ids = order or [f"@juror-{index:02d}" for index in range(12)]
    accounts = {
        account_id: {
            "nonce": 0,
            "poh_tier": 2,
            "poh_status": "active",
            "banned": False,
            "locked": False,
            "reputation_milli": 10_000,
        }
        for account_id in ids
    }
    accounts["@subject"] = {
        "nonce": 0,
        "poh_tier": 0,
        "poh_status": "pending",
        "banned": False,
        "locked": False,
        "reputation_milli": 0,
    }
    return {
        "chain_id": "property-chain",
        "height": 100,
        "tip": "b100",
        "accounts": accounts,
        "params": {
            "allow_case_scoped_juror_without_role": True,
        },
    }


def _chain_state(height: int = 8, *, max_records: int = 4, finalized_height: int = 5) -> dict:
    blocks = {}
    for h in range(1, height + 1):
        blocks[f"b{h}"] = {
            "height": h,
            "prev_block_id": f"b{h - 1}" if h > 1 else "",
            "block_ts_ms": h * 1_000,
        }
    return {
        "height": height,
        "tip": f"b{height}",
        "blocks": blocks,
        "accounts": {},
        "meta": {"consensus_block_history_max_records": max_records},
        "finalized": {"height": finalized_height, "block_id": f"b{finalized_height}"},
    }


def _env(*, signer: str, nonce: int, pubkey: str) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "chain_id": "weall-prod",
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "sig_profile": "pq-mldsa-v1",
            "payload": {
                "pubkey": pubkey,
                "recovery_pubkey": "recovery-a",
                "recovery_sig_profile": "pq-mldsa-v1",
                "evidence_kem_pubkey": "kem-a",
                "evidence_kem_algorithm": "ml-kem-768",
            },
            "parent": None,
        }
    )


def _work_state(bits: int = 4) -> dict:
    return {
        "chain_id": "weall-prod",
        "accounts": {},
        "params": {
            "account_registration_work_required": True,
            "account_registration_work_difficulty_bits": bits,
        },
    }


def _solve(env: TxEnvelope, bits: int) -> int:
    for nonce in range(1_000_000):
        if leading_zero_bits(account_registration_work_digest(env, nonce)) >= bits:
            return nonce
    raise AssertionError("property work solution not found")


def _with_work(env: TxEnvelope, *, bits: int) -> TxEnvelope:
    work_nonce = _solve(env, bits)
    raw = env.to_json()
    raw["payload"] = dict(raw["payload"])
    raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
    raw["payload"]["registration_work_nonce"] = work_nonce
    return TxEnvelope.from_json(raw)


def test_property_state_root_and_live_juror_order_are_mapping_order_invariant() -> None:
    base = _reviewer_state()
    expected_root = compute_state_root(base)
    expected_jurors = eligible_live_jurors(
        state=base,
        allow_roleless_bootstrap=True,
    )

    for seed, rng in property_cases(
        "property_state_root_and_live_juror_order_are_mapping_order_invariant"
    ):
        permuted = _permute(base, rng)
        assert compute_state_root(permuted) == expected_root, property_reproducer(
            "property_state_root_and_live_juror_order_are_mapping_order_invariant", seed
        )
        got = eligible_live_jurors(
            state=permuted,
            allow_roleless_bootstrap=True,
        )
        assert got == expected_jurors, property_reproducer(
            "property_state_root_and_live_juror_order_are_mapping_order_invariant", seed
        )


def test_property_async_case_labels_cannot_grind_panel() -> None:
    for seed, rng in property_cases("property_async_case_labels_cannot_grind_panel"):
        ids = [f"@juror-{index:02d}" for index in range(12)]
        rng.shuffle(ids)
        state = _reviewer_state(ids)
        labels = [f"applicant-label-{seed}-{index}" for index in range(128)]
        rng.shuffle(labels)
        panels = {
            tuple(
                pick_async_jurors(
                    state=state,
                    case_id=label,
                    target_account="@subject",
                    n_jurors=3,
                    min_rep_units=0,
                    allow_roleless_bootstrap=True,
                    selection_seed=f"committed-request-seed-{seed}",
                )
            )
            for label in labels
        }
        assert len(panels) == 1, property_reproducer(
            "property_async_case_labels_cannot_grind_panel", seed
        )


def test_property_bounded_history_projection_is_mapping_order_invariant() -> None:
    base = _chain_state()
    expected = project_bounded_block_history_state(base)
    expected_root = compute_state_root(base)

    assert len(expected["blocks"]) == 4
    assert BLOCK_HISTORY_CHECKPOINT_KEY in expected

    for seed, rng in property_cases(
        "property_bounded_history_projection_is_mapping_order_invariant"
    ):
        permuted = _permute(base, rng)
        projected = project_bounded_block_history_state(permuted)
        assert compute_state_root(permuted) == expected_root, property_reproducer(
            "property_bounded_history_projection_is_mapping_order_invariant", seed
        )
        assert projected["blocks"] == expected["blocks"], property_reproducer(
            "property_bounded_history_projection_is_mapping_order_invariant", seed
        )
        assert projected[BLOCK_HISTORY_CHECKPOINT_KEY] == expected[BLOCK_HISTORY_CHECKPOINT_KEY], (
            property_reproducer(
                "property_bounded_history_projection_is_mapping_order_invariant", seed
            )
        )


def test_property_registration_work_is_bound_to_signer_nonce_and_payload() -> None:
    bits = 4
    for seed, rng in property_cases(
        "property_registration_work_is_bound_to_signer_nonce_and_payload"
    ):
        base = _with_work(_env(signer=f"@base-{seed}", nonce=1, pubkey="pk-a"), bits=bits)
        ok, reason, _ = verify_account_registration_work(_work_state(bits), base)
        assert ok is True and reason == ""

        work_nonce = base.payload["registration_work_nonce"]
        variants = [
            _env(
                signer=f"@other-{seed}-{rng.randrange(1_000_000)}",
                nonce=1,
                pubkey="pk-a",
            ),
            _env(signer=f"@base-{seed}", nonce=2 + rng.randrange(8), pubkey="pk-a"),
            _env(
                signer=f"@base-{seed}",
                nonce=1,
                pubkey=f"pk-{rng.randrange(1_000_000)}",
            ),
        ]
        for variant in variants:
            raw = variant.to_json()
            raw["payload"] = dict(raw["payload"])
            raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
            raw["payload"]["registration_work_nonce"] = work_nonce
            variant_with_work = TxEnvelope.from_json(raw)
            accepted, _, _ = verify_account_registration_work(_work_state(bits), variant_with_work)
            assert accepted is False, property_reproducer(
                "property_registration_work_is_bound_to_signer_nonce_and_payload", seed
            )
