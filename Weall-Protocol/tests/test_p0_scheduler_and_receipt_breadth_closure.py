from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.scheduler_pipeline import (
    run_leader_pre_schedulers,
    run_replay_pre_schedulers,
)
from weall.runtime.state_hash import compute_state_root


def _reviewer_record() -> dict:
    return {
        "active": True,
        "responsibilities": {
            "reviewer": {
                "poh_async_review": {"opted_in": True, "active": True},
                "poh_live_review": {"opted_in": True, "active": True},
            }
        },
    }


def _accounts(order: tuple[str, ...]) -> dict:
    records = {
        "@alice": {"poh_tier": 1, "reputation_milli": 0},
        "@bob": {"poh_tier": 1, "reputation_milli": 0},
        "@j1": {"poh_tier": 2, "reputation_milli": 5000},
        "@j2": {"poh_tier": 2, "reputation_milli": 5000},
        "@j3": {"poh_tier": 2, "reputation_milli": 5000},
    }
    return {account_id: copy.deepcopy(records[account_id]) for account_id in order}


def _roles(order: tuple[str, ...]) -> dict:
    return {
        "jurors": {
            "by_id": {account_id: _reviewer_record() for account_id in order},
            "active_set": sorted(order),
        }
    }


def _base_state(
    *,
    account_order: tuple[str, ...],
    reviewer_order: tuple[str, ...],
) -> dict:
    return {
        "height": 10,
        "tip": "b10",
        "tip_hash": "b10",
        "accounts": _accounts(account_order),
        "roles": _roles(reviewer_order),
        "params": {
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_min_rep_milli": 0,
                "tier2_n_jurors": 3,
                "tier2_min_total_reviews": 3,
                "tier2_pass_threshold": 2,
                "tier2_fail_max": 1,
                "tier2_min_rep_milli": 0,
                "live_min_rep_milli": 0,
                "live_partial_panels_enabled": True,
            }
        },
        "system_queue": [],
    }


def _assignment_state(
    case_order: tuple[str, str],
    *,
    account_order: tuple[str, ...],
    reviewer_order: tuple[str, ...],
) -> dict:
    state = _base_state(account_order=account_order, reviewer_order=reviewer_order)
    async_cases = {}
    tier2_cases = {}
    live_cases = {}
    for case_id in case_order:
        account_id = "@alice" if case_id == "case-a" else "@bob"
        async_cases[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "status": "open",
            "followup_round": 0,
            "evidence_binds": {"bind-1": {"followup_round": 0}},
            "assigned_juror_count": 3,
            "assigned_jurors": [],
        }
        tier2_cases[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "status": "open",
            "jurors": {},
        }
        live_cases[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "status": "open",
            "jurors": {},
        }
    state["poh"] = {
        "async_cases": async_cases,
        "tier2_cases": tier2_cases,
        "live_cases": live_cases,
    }
    return state


def _finalize_state(case_order: tuple[str, str]) -> dict:
    state = _base_state(
        account_order=("@alice", "@bob", "@j1", "@j2", "@j3"),
        reviewer_order=("@j1", "@j2", "@j3"),
    )
    async_cases = {}
    tier2_cases = {}
    live_cases = {}
    for case_id in case_order:
        account_id = "@alice" if case_id == "case-a" else "@bob"
        async_cases[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "status": "under_review",
            "followup_round": 0,
            "evidence_binds": {"bind-1": {"followup_round": 0}},
            "assigned_juror_count": 3,
            "assigned_jurors": ["@j1", "@j2", "@j3"],
            "minimum_reviews": 3,
            "approval_threshold": 2,
            "rejection_threshold": 2,
            "reviews": {
                "@j1": {"followup_round": 0, "verdict": "approve"},
                "@j2": {"followup_round": 0, "verdict": "approve"},
                "@j3": {"followup_round": 0, "verdict": "reject"},
            },
        }
        tier2_cases[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "status": "under_review",
            "jurors": {
                "@j1": {"verdict": "pass"},
                "@j2": {"verdict": "pass"},
                "@j3": {"verdict": "fail"},
            },
        }
        live_cases[case_id] = {
            "case_id": case_id,
            "account_id": account_id,
            "status": "open",
            "jurors": {
                "@j1": {
                    "role": "interacting",
                    "accepted": True,
                    "attended": True,
                    "verdict": "pass",
                },
                "@j2": {
                    "role": "interacting",
                    "accepted": True,
                    "attended": True,
                    "verdict": "pass",
                },
            },
        }
    state["poh"] = {
        "async_cases": async_cases,
        "tier2_cases": tier2_cases,
        "live_cases": live_cases,
    }
    return state


def _queue_projection(state: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for item in state.get("system_queue", []):
        if not isinstance(item, dict):
            continue
        payload = item.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        out.append(
            (
                str(item.get("tx_type") or ""),
                str(payload.get("case_id") or ""),
            )
        )
    return out


@pytest.mark.parametrize(
    "scheduler",
    [
        schedule_poh_async_system_txs,
        schedule_poh_tier2_system_txs,
        schedule_poh_live_system_txs,
    ],
)
def test_p0_02_equal_root_assignment_permutations_schedule_identical_work(
    scheduler,
) -> None:
    """A04-F001/A16-F003: assignment cannot consume JSON insertion order."""

    state_a = _assignment_state(
        ("case-a", "case-b"),
        account_order=("@alice", "@bob", "@j1", "@j2", "@j3"),
        reviewer_order=("@j1", "@j2", "@j3"),
    )
    state_b = _assignment_state(
        ("case-b", "case-a"),
        account_order=("@j3", "@j2", "@j1", "@bob", "@alice"),
        reviewer_order=("@j3", "@j2", "@j1"),
    )

    assert compute_state_root(state_a) == compute_state_root(state_b)

    scheduler(state_a, next_height=11)
    scheduler(state_b, next_height=11)

    assert state_a["system_queue"] == state_b["system_queue"]
    assert compute_state_root(state_a) == compute_state_root(state_b)
    projection = _queue_projection(state_a)
    assert projection
    assert [case_id for _tx_type, case_id in projection] == sorted(
        case_id for _tx_type, case_id in projection
    )


@pytest.mark.parametrize(
    "scheduler",
    [
        schedule_poh_async_system_txs,
        schedule_poh_tier2_system_txs,
        schedule_poh_live_system_txs,
    ],
)
def test_p0_02_equal_root_finalize_permutations_schedule_identical_work(
    scheduler,
) -> None:
    """A04-F001/A16-F003: finalize/receipt work is equal-root deterministic."""

    state_a = _finalize_state(("case-a", "case-b"))
    state_b = _finalize_state(("case-b", "case-a"))

    assert compute_state_root(state_a) == compute_state_root(state_b)

    scheduler(state_a, next_height=11)
    scheduler(state_b, next_height=11)

    assert state_a["system_queue"] == state_b["system_queue"]
    assert compute_state_root(state_a) == compute_state_root(state_b)
    projection = _queue_projection(state_a)
    assert projection
    assert [case_id for _tx_type, case_id in projection] == sorted(
        case_id for _tx_type, case_id in projection
    )


def test_p0_02_equal_root_poh_pipeline_matches_leader_and_replay() -> None:
    """A04-F001/A16-F003/A18-F001: leader/replay derive identical PoH work."""

    leader = _finalize_state(("case-a", "case-b"))
    follower = _finalize_state(("case-b", "case-a"))

    assert compute_state_root(leader) == compute_state_root(follower)

    run_leader_pre_schedulers(leader, next_height=11)
    run_replay_pre_schedulers(follower, next_height=11)

    assert leader == follower
    assert compute_state_root(leader) == compute_state_root(follower)
    assert _queue_projection(leader)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="p0-a06-follower-closure",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def test_p0_04_follower_rejects_receipt_body_tamper_and_restart_preserves_canonical_block(
    tmp_path: Path,
) -> None:
    """A06-F001/A16-F002: replay/readback binds canonical receipts."""

    leader = _executor(tmp_path, "leader")
    submitted = leader.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:@alice"},
        }
    )
    assert submitted["ok"] is True
    produced = leader.produce_block(max_txs=1)
    assert produced.ok is True
    canonical = leader.get_block_by_height(1)
    assert isinstance(canonical, dict)
    assert isinstance(canonical.get("receipts"), list)
    assert canonical["receipts"]

    forged = copy.deepcopy(canonical)
    forged["receipts"][0]["signer"] = "@forged"

    follower = _executor(tmp_path, "follower")
    before = copy.deepcopy(follower.state)
    rejected = follower.apply_block(forged)
    assert rejected.ok is False
    assert follower.state == before
    assert follower.get_block_by_height(1) is None

    accepted = follower.apply_block(copy.deepcopy(canonical))
    assert accepted.ok is True
    assert follower.get_block_by_height(1) == canonical
    assert compute_state_root(follower.state) == compute_state_root(leader.state)

    restarted = _executor(tmp_path, "follower")
    assert restarted.get_block_by_height(1) == canonical
    assert compute_state_root(restarted.state) == compute_state_root(leader.state)
