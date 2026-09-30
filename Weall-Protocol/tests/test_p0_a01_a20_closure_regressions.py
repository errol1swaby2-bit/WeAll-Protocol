from __future__ import annotations

import copy

import pytest

from weall.runtime.block_commit import commit_block_candidate
from weall.runtime.block_hash import compute_block_hash, compute_receipts_root
from weall.runtime.block_id import compute_block_id
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.runtime_context import RuntimeContext
from weall.runtime.state_hash import compute_state_root


def test_block_inclusion_context_forces_nonce_consumption_on_apply_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A02-F001: canonical inclusion must make a failed user tx one-shot."""

    from weall.runtime import executor as executor_mod

    seen: list[bool] = []

    def fake_apply(state, env, *, consume_nonce_on_fail: bool = False):
        del state, env
        seen.append(bool(consume_nonce_on_fail))
        return None

    monkeypatch.setattr(executor_mod, "apply_tx_atomic_meta", fake_apply)
    apply_fn = RuntimeContext.from_executor(object()).tx_execution_set.apply_tx_atomic_meta

    apply_fn({}, object(), consume_nonce_on_fail=False)

    assert seen == [True]


def _tier2_receipt_state(order: tuple[str, str]) -> dict:
    cases = {
        case_id: {
            "case_id": case_id,
            "account_id": f"@{case_id}",
            "status": "awarded",
            "tier2_receipt_emitted": False,
        }
        for case_id in order
    }
    return {"height": 10, "tip": "b10", "poh": {"tier2_cases": cases}, "system_queue": []}


def _async_receipt_state(order: tuple[str, str]) -> dict:
    cases = {
        case_id: {
            "case_id": case_id,
            "account_id": f"@{case_id}",
            "status": "approved",
            "outcome": "approved",
        }
        for case_id in order
    }
    return {"height": 10, "tip": "b10", "poh": {"async_cases": cases}, "system_queue": []}


def _live_receipt_state(order: tuple[str, str]) -> dict:
    cases = {
        case_id: {
            "case_id": case_id,
            "account_id": f"@{case_id}",
            "status": "awarded",
            "live_receipt_emitted": False,
        }
        for case_id in order
    }
    return {"height": 10, "tip": "b10", "poh": {"live_cases": cases}, "system_queue": []}


@pytest.mark.parametrize(
    ("factory", "scheduler"),
    [
        (_tier2_receipt_state, schedule_poh_tier2_system_txs),
        (_async_receipt_state, schedule_poh_async_system_txs),
        (_live_receipt_state, schedule_poh_live_system_txs),
    ],
)
def test_equal_root_poh_case_permutations_schedule_identical_system_work(factory, scheduler) -> None:
    """A04-F001/A16-F003: mapping insertion order cannot affect consensus work."""

    state_a = factory(("case-a", "case-b"))
    state_b = factory(("case-b", "case-a"))

    assert compute_state_root(state_a) == compute_state_root(state_b)

    scheduler(state_a, next_height=11)
    scheduler(state_b, next_height=11)

    assert state_a["system_queue"] == state_b["system_queue"]
    assert compute_state_root(state_a) == compute_state_root(state_b)

    payload_case_ids = [
        str(item.get("payload", {}).get("case_id") or "")
        for item in state_a["system_queue"]
        if isinstance(item, dict)
    ]
    assert payload_case_ids == sorted(payload_case_ids)


def _complete_empty_block(*, chain_id: str = "weall-p0-test") -> dict:
    receipts: list[dict] = []
    receipts_root = compute_receipts_root(receipts=receipts)
    header = {
        "chain_id": chain_id,
        "height": 1,
        "block_ts_ms": 1_000,
        "prev_block_hash": "0" * 64,
        "tx_ids": [],
        "receipts_root": receipts_root,
    }
    block_id = compute_block_id(
        chain_id=chain_id,
        height=1,
        prev_block_id="genesis",
        prev_block_hash=header["prev_block_hash"],
        ts_ms=header["block_ts_ms"],
        node_id="@validator",
        tx_ids=[],
        receipts_root=receipts_root,
    )
    return {
        "chain_id": chain_id,
        "height": 1,
        "block_ts_ms": header["block_ts_ms"],
        "prev_block_id": "genesis",
        "prev_block_hash": header["prev_block_hash"],
        "proposer": "@validator",
        "txs": [],
        "receipts": receipts,
        "header": header,
        "block_id": block_id,
        "block_hash": compute_block_hash(header=header),
    }


def test_durable_commit_rejects_unbound_received_receipt_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A06-F001: durable commit must not persist receipt metadata replay did not bind."""

    from weall.runtime import block_commit as block_commit_mod

    class DummyExecutor:
        chain_id = "weall-p0-test"

    monkeypatch.setattr(block_commit_mod, "prune_emitted_system_queue", lambda state: None)

    block = _complete_empty_block()
    malformed = copy.deepcopy(block)
    malformed["receipts"] = [
        {
            "tx_id": "tx:attacker-controlled-alias",
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@victim",
            "nonce": 999,
            "ok": False,
        }
    ]

    meta = commit_block_candidate(
        DummyExecutor(),
        block=malformed,
        new_state={"height": 1, "tip": block["block_id"], "system_queue": []},
        applied_ids=[],
        invalid_ids=[],
    )

    assert meta.ok is False
