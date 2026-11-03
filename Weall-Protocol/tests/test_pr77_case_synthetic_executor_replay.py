"""Synthetic canonical producer/follower CASE queue exercise (NO-GO).

Tests deliberately seed matching SYSTEM queues into disposable local executors.
That is NOT evidence a real authorized scheduler could produce those receipts,
and it does not establish historical compatibility or public-testnet readiness.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import enqueue_system_tx

CHAIN = "case-queue-synthetic-replay"


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.sqlite"),
        node_id=name,
        chain_id=CHAIN,
        tx_index_path=str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"),
    )


def _seed_queued_case(executor: WeAllExecutor, *, payloads: list[dict]) -> None:
    assert executor.read_state()["height"] == 0
    state = executor.read_state()
    for payload in payloads:
        enqueue_system_tx(
            state,
            tx_type="CASE_BIND_TO_DISPUTE",
            payload=copy.deepcopy(payload),
            due_height=1,
            signer="SYSTEM",
            parent="synthetic:case-opening",
            phase="post",
        )
    executor.state = state
    executor._ledger_store.write(executor.state)


def _case_txs(block: dict) -> list[dict]:
    return [
        tx
        for tx in block["txs"]
        if isinstance(tx, dict) and tx.get("tx_type") == "CASE_BIND_TO_DISPUTE"
    ]


@pytest.mark.parametrize(
    "payloads",
    [
        [{"case_id": "case-a", "dispute_id": "dispute-original"}],
        [
            {"case_id": "case-a", "dispute_id": "dispute-original"},
            {"case_id": "case-a", "dispute_id": "dispute-conflicting"},
        ],
    ],
)
def test_synthetic_queued_case_receipts_commit_replay_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payloads: list[dict]
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    source = _executor(tmp_path, "source")
    follower = _executor(tmp_path, "follower")
    for executor in (source, follower):
        _seed_queued_case(executor, payloads=payloads)

    initial = copy.deepcopy(source.read_state())
    assert compute_state_root(initial) == compute_state_root(follower.read_state())

    produced = source.produce_block(max_txs=0, allow_empty=True)
    assert produced.ok is True, produced.error
    block = source.get_block_by_height(1)
    assert isinstance(block, dict)
    cases = _case_txs(block)
    assert len(cases) == len(payloads)
    assert len([r for r in block["receipts"] if r.get("tx_type") == "CASE_BIND_TO_DISPUTE"]) == len(
        payloads
    )
    assert all(
        r.get("ok") is True for r in block["receipts"] if r.get("tx_type") == "CASE_BIND_TO_DISPUTE"
    )

    stored = source.read_state()["cases"]["bindings"]["case-a"]
    assert stored["dispute_id"] == "dispute-original"
    if len(payloads) == 2:
        # KNOWN HOLD: both queued transactions are acknowledged, but only
        # the first case binding is stored. This is an observed synthetic
        # consensus-path contract, NOT authorization of the second request.
        assert cases[1]["payload"]["dispute_id"] == "dispute-conflicting"
        assert cases[1]["payload"]["dispute_id"] != stored["dispute_id"]

    replayed = follower.apply_block(copy.deepcopy(block))
    assert replayed.ok is True, replayed.error
    assert compute_state_root(source.read_state()) == compute_state_root(follower.read_state())
    for name in ("source", "follower"):
        restarted = _executor(tmp_path, name)
        assert restarted.get_block_by_height(1) == block
        assert compute_state_root(restarted.read_state()) == compute_state_root(source.read_state())


def test_malformed_queued_system_case_never_commits_partial_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    source = _executor(tmp_path, "bad-queue")
    _seed_queued_case(source, payloads=[{"case_id": "case-a"}])  # missing dispute_id
    original = source.read_state()
    original_root = compute_state_root(original)
    result = source.produce_block(max_txs=0, allow_empty=True)
    assert result.ok is False
    assert "system_tx_" in str(result.error), result.error
    assert source.get_block_by_height(1) is None
    assert source.read_state() == original
    assert compute_state_root(source.read_state()) == original_root
    restarted = _executor(tmp_path, "bad-queue")
    assert restarted.get_block_by_height(1) is None
    assert restarted.read_state() == original
