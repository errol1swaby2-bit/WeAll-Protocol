from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.gov_engine import tick_governance_lifecycle
from weall.runtime.scheduler_pipeline import (
    run_leader_pre_schedulers,
    run_replay_pre_schedulers,
)
from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.tx.canon import TxIndex


def _gov_state(ids: tuple[str, str]) -> dict:
    return {
        "height": 1,
        "system_queue": [],
        "gov_proposals_by_id": {
            pid: {
                "proposal_id": pid,
                "stage": "draft",
                "created_at_height": 1,
                "rules": {"auto_lifecycle": True, "draft_period_blocks": 0},
            }
            for pid in ids
        },
    }


def _dispute_state(ids: tuple[str, str]) -> dict:
    return {
        "height": 1,
        "system_queue": [],
        "meta": {"constitutional_clock": {"enabled": True}},
        "disputes_by_id": {
            did: {
                "stage": "appeal_resolved",
                "appeal_panel_round": 1,
                "appeal_panel_result": {
                    "reached": True,
                    "resolution": {"outcome": "upheld"},
                },
            }
            for did in ids
        },
    }


def _queue_ids(state: dict) -> list[str]:
    return [str(item["queue_id"]) for item in state["system_queue"]]


def _persist_restart(tmp_path: Path, state: dict) -> dict:
    path = str(tmp_path / "node.db")
    db = SqliteDB(path=path)
    db.init_schema()
    SqliteLedgerStore(db=db).write(state)
    return SqliteLedgerStore(db=SqliteDB(path=path)).read()


def _emitted_pre(state: dict) -> list[tuple[str, str, dict]]:
    index = TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )
    return [
        (env.tx_type, str(env.parent or ""), dict(env.payload))
        for env in system_tx_emitter(state, index, next_height=2, phase="pre")
    ]


def test_governance_scheduler_orders_outer_ids_regardless_of_insertion_order() -> None:
    left = _gov_state(("z", "a"))
    right = _gov_state(("a", "z"))
    assert compute_state_root(left) == compute_state_root(right)

    assert tick_governance_lifecycle(left, next_height=2) == 2
    assert tick_governance_lifecycle(right, next_height=2) == 2
    assert [x["payload"]["proposal_id"] for x in left["system_queue"]] == ["a", "z"]
    assert _queue_ids(left) == _queue_ids(right)
    assert compute_state_root(left) == compute_state_root(right)


def test_dispute_scheduler_orders_outer_ids_regardless_of_insertion_order() -> None:
    left = _dispute_state(("z", "a"))
    right = _dispute_state(("a", "z"))
    assert compute_state_root(left) == compute_state_root(right)

    assert tick_dispute_lifecycle(left, next_height=2) == 2
    assert tick_dispute_lifecycle(right, next_height=2) == 2
    assert [x["payload"]["dispute_id"] for x in left["system_queue"]] == ["a", "z"]
    assert [x["payload"]["receipt_id"] for x in left["system_queue"]] == [
        "receipt:dispute:a:appeal-panel-finalize:1",
        "receipt:dispute:z:appeal-panel-finalize:1",
    ]
    assert _queue_ids(left) == _queue_ids(right)
    assert compute_state_root(left) == compute_state_root(right)


def test_leader_and_replay_pre_scheduler_queue_and_state_roots_match() -> None:
    leader = _gov_state(("z", "a"))
    follower = _gov_state(("a", "z"))
    run_leader_pre_schedulers(leader, next_height=2)
    run_replay_pre_schedulers(follower, next_height=2)
    assert _queue_ids(leader) == _queue_ids(follower)
    assert compute_state_root(leader) == compute_state_root(follower)


def test_sqlite_restart_reorders_map_but_not_mandatory_governance_queue(tmp_path: Path) -> None:
    in_memory = _gov_state(("z", "a"))
    restarted = _persist_restart(tmp_path, copy.deepcopy(in_memory))
    assert compute_state_root(in_memory) == compute_state_root(restarted)

    tick_governance_lifecycle(in_memory, next_height=2)
    tick_governance_lifecycle(restarted, next_height=2)
    assert _queue_ids(in_memory) == _queue_ids(restarted)
    assert _emitted_pre(in_memory) == _emitted_pre(restarted)
    assert compute_state_root(in_memory) == compute_state_root(restarted)


def test_sqlite_restart_reorders_map_but_not_mandatory_dispute_queue(tmp_path: Path) -> None:
    in_memory = _dispute_state(("z", "a"))
    restarted = _persist_restart(tmp_path, copy.deepcopy(in_memory))
    assert compute_state_root(in_memory) == compute_state_root(restarted)

    tick_dispute_lifecycle(in_memory, next_height=2)
    tick_dispute_lifecycle(restarted, next_height=2)
    assert _queue_ids(in_memory) == _queue_ids(restarted)
    assert _emitted_pre(in_memory) == _emitted_pre(restarted)
    assert compute_state_root(in_memory) == compute_state_root(restarted)


def test_clean_database_two_block_governance_replay_and_tamper_rejection(
    tmp_path: Path, monkeypatch
) -> None:
    """Exercise real block construction/replay from separately seeded clean SQLite nodes.

    The only supported history is the one constructed within this test. There
    is no import of previous devnet snapshots or old insertion-order blocks.
    """
    import weall.runtime.block_builder as block_builder
    import weall.runtime.block_replay as block_replay
    from weall.runtime.executor import WeAllExecutor

    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)

    chain_id = "rem-w1a-isolated-clean-genesis-v1"
    seed = {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {},
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
        "gov_proposals_by_id": {
            pid: {
                "proposal_id": pid,
                "stage": "draft",
                "created_at_height": 1,
                "rules": {"auto_lifecycle": True, "draft_period_blocks": 0},
            }
            for pid in ("z", "a")
        },
    }
    index_path = str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    # Derive the exact current genesis metadata from a real freshly initialized
    # executor. Never fake or bypass the persisted state-root-version guard.
    template_path = tmp_path / "template" / "node.db"
    template_path.parent.mkdir(parents=True, exist_ok=True)
    template = WeAllExecutor(
        db_path=str(template_path), node_id="@node", chain_id=chain_id, tx_index_path=index_path
    )
    # Use the complete initialized genesis as the source of truth. Supplying
    # only an artificial minimal state misses consensus-bound default fields
    # that the executor validates at restart.
    pending_proposals = copy.deepcopy(seed["gov_proposals_by_id"])
    seed = copy.deepcopy(template.state)
    assert seed.get("height") == 0
    seed["gov_proposals_by_id"] = pending_proposals
    seed["system_queue"] = []

    def node(label: str, *, fresh: bool) -> WeAllExecutor:
        path = tmp_path / label / "node.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        executor = WeAllExecutor(
            db_path=str(path), node_id="@node", chain_id=chain_id, tx_index_path=index_path
        )
        if fresh:
            executor._ledger_store.write_state_snapshot(copy.deepcopy(seed))
            executor.state = executor._ledger_store.read()
        return executor

    leader = node("leader", fresh=True)
    follower = node("follower", fresh=True)
    adversary = node("tampered-follower", fresh=True)
    assert compute_state_root(leader.state) == compute_state_root(follower.state)

    def candidate_and_commit(*, height: int) -> dict:
        block, new_state, applied, invalid, err = leader.build_block_candidate(
            max_txs=0, allow_empty=True, force_ts_ms=height * 1000
        )
        assert err == ""
        assert isinstance(block, dict)
        assert isinstance(new_state, dict)
        outcome = leader.commit_block_candidate(
            block=block, new_state=new_state, applied_ids=applied, invalid_ids=invalid
        )
        assert outcome.ok, outcome.error
        return block

    first = candidate_and_commit(height=1)
    first_replay = follower.apply_block(first)
    assert first_replay.ok, first_replay.error
    assert adversary.apply_block(first).ok
    assert compute_state_root(leader.state) == compute_state_root(follower.state)

    second = candidate_and_commit(height=2)
    queue_prefix = [tx for tx in second["txs"] if isinstance(tx, dict) and tx.get("system") is True]
    assert [tx["tx_type"] for tx in queue_prefix] == ["GOV_STAGE_SET", "GOV_STAGE_SET"]
    assert [tx["payload"]["proposal_id"] for tx in queue_prefix] == ["a", "z"]
    assert all(tx["payload"].get("_system_queue_id") for tx in queue_prefix)

    swapped = copy.deepcopy(second)
    swapped["txs"][0], swapped["txs"][1] = swapped["txs"][1], swapped["txs"][0]
    untouched = copy.deepcopy(adversary.state)
    rejected = adversary.apply_block(swapped)
    assert rejected.ok is False
    # A raw reorder must first fail the committed tx-ID header binding. The
    # separate SYSTEM-completeness regression exercises the scheduler-order gate.
    assert rejected.error == "bad_block:header_tx_ids_mismatch"
    assert adversary.state == untouched

    second_replay = follower.apply_block(second)
    assert second_replay.ok, second_replay.error
    assert compute_state_root(leader.state) == compute_state_root(follower.state)
    assert leader.state.get("gov_stage_set_receipts") == follower.state.get(
        "gov_stage_set_receipts"
    )
    assert len(leader.state.get("gov_stage_set_receipts") or []) >= 2

    committed_root = compute_state_root(leader.state)
    leader_restart = node("leader", fresh=False)
    follower_restart = node("follower", fresh=False)
    assert compute_state_root(leader_restart.state) == committed_root
    assert compute_state_root(leader_restart.state) == compute_state_root(follower_restart.state)
    assert leader_restart.state.get("gov_stage_set_receipts") == follower_restart.state.get(
        "gov_stage_set_receipts"
    )


def test_clean_database_two_block_dispute_replay_omission_reorder_and_restart(
    tmp_path: Path, monkeypatch
) -> None:
    """Native dispute SYSTEM block proof on an isolated, never-imported genesis.

    Exercises the canonical mandatory prefix through real leader construction,
    two independent follower replay paths, raw tamper rejection, receipts and
    independently restarted SQLite roots. It does not establish peer-authenticated
    networking or independent external operator evidence.
    """
    import weall.runtime.block_builder as block_builder
    import weall.runtime.block_replay as block_replay
    from weall.runtime.executor import WeAllExecutor

    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)

    chain_id = "rem-w1a-dispute-clean-genesis-v1"
    index_path = str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")

    template_path = tmp_path / "template" / "node.db"
    template_path.parent.mkdir(parents=True, exist_ok=True)
    template = WeAllExecutor(
        db_path=str(template_path), node_id="@node", chain_id=chain_id, tx_index_path=index_path
    )
    seed = copy.deepcopy(template.state)
    assert seed.get("height") == 0
    seed["meta"] = dict(seed.get("meta") or {})
    seed["meta"]["constitutional_clock"] = {
        "enabled": True,
        "genesis_time_ms": 0,
    }
    seed["system_queue"] = []
    seed["disputes_by_id"] = {
        did: {
            "dispute_id": did,
            "stage": "appeal_window",
            "appeal_deadline_height": 1,
            "resolution": {"outcome": "no_action", "actions": []},
            "jurors": {},
        }
        for did in ("z", "a")
    }

    def node(label: str, *, fresh: bool, reverse: bool = False) -> WeAllExecutor:
        path = tmp_path / label / "node.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        executor = WeAllExecutor(
            db_path=str(path), node_id="@node", chain_id=chain_id, tx_index_path=index_path
        )
        if fresh:
            state = copy.deepcopy(seed)
            if reverse:
                disputes = state["disputes_by_id"]
                state["disputes_by_id"] = {did: disputes[did] for did in ("a", "z")}
            executor._ledger_store.write_state_snapshot(state)
            executor.state = executor._ledger_store.read()
        return executor

    leader = node("leader", fresh=True)
    follower = node("follower", fresh=True, reverse=True)
    adversary = node("adversary", fresh=True, reverse=True)
    assert compute_state_root(leader.state) == compute_state_root(follower.state)
    assert compute_state_root(leader.state) == compute_state_root(adversary.state)

    def candidate_and_commit() -> dict:
        block, new_state, applied, invalid, error = leader.build_block_candidate(
            max_txs=0, allow_empty=True
        )
        assert error == ""
        assert isinstance(block, dict)
        assert isinstance(new_state, dict)
        outcome = leader.commit_block_candidate(
            block=block, new_state=new_state, applied_ids=applied, invalid_ids=invalid
        )
        assert outcome.ok, outcome.error
        return block

    first = candidate_and_commit()
    assert follower.apply_block(first).ok
    assert adversary.apply_block(first).ok
    assert compute_state_root(leader.state) == compute_state_root(follower.state)

    second = candidate_and_commit()
    system_txs = [tx for tx in second["txs"] if isinstance(tx, dict) and tx.get("system") is True]
    assert [tx["tx_type"] for tx in system_txs] == [
        "DISPUTE_FINAL_RECEIPT",
        "DISPUTE_FINAL_RECEIPT",
    ]
    assert [tx["payload"]["dispute_id"] for tx in system_txs] == ["a", "z"]
    assert all(tx["payload"].get("_system_queue_id") for tx in system_txs)
    assert all(tx["payload"].get("appeal_window_closed") is True for tx in system_txs)

    pre_attack_root = compute_state_root(adversary.state)
    reordered = copy.deepcopy(second)
    reordered["txs"][0], reordered["txs"][1] = (
        reordered["txs"][1],
        reordered["txs"][0],
    )
    reorder_outcome = adversary.apply_block(reordered)
    assert not reorder_outcome.ok
    assert reorder_outcome.error == "bad_block:header_tx_ids_mismatch"
    assert compute_state_root(adversary.state) == pre_attack_root

    omitted = copy.deepcopy(second)
    omitted["txs"].pop(0)
    omission_outcome = adversary.apply_block(omitted)
    assert not omission_outcome.ok
    assert omission_outcome.error == "bad_block:header_tx_ids_mismatch"
    assert compute_state_root(adversary.state) == pre_attack_root

    accepted = follower.apply_block(second)
    assert accepted.ok, accepted.error
    assert compute_state_root(leader.state) == compute_state_root(follower.state)
    assert leader.state.get("dispute_receipts") == follower.state.get("dispute_receipts")
    assert len(leader.state.get("dispute_receipts") or {}) >= 2
    for did in ("a", "z"):
        assert leader.state["disputes_by_id"][did]["stage"] == "finalized"

    committed_root = compute_state_root(leader.state)
    restarted_leader = node("leader", fresh=False)
    restarted_follower = node("follower", fresh=False)
    assert compute_state_root(restarted_leader.state) == committed_root
    assert compute_state_root(restarted_follower.state) == committed_root
    assert restarted_leader.state.get("dispute_receipts") == (
        restarted_follower.state.get("dispute_receipts")
    )
