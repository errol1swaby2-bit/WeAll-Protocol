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
