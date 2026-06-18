from __future__ import annotations

from pathlib import Path
from typing import Any

from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _new_executor(tmp_path: Path, name: str, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id="@leader",
        chain_id=chain_id,
        tx_index_path=_tx_index_path(),
    )


def _write_state(ex: WeAllExecutor, state: dict[str, Any]) -> None:
    ex._ledger_store.write_state_snapshot(state)  # type: ignore[attr-defined]
    ex.state = ex._ledger_store.read()  # type: ignore[attr-defined]


def _bootstrap_helper_state(ex: WeAllExecutor, *, account_id: str = "@alice") -> None:
    state = dict(ex.state)
    accounts = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}
    accounts[account_id] = {
        "pubkeys": [f"k:{account_id}"],
        "nonce": 1,
        "poh_tier": 2,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    state["accounts"] = accounts
    consensus = state.get("consensus") if isinstance(state.get("consensus"), dict) else {}
    consensus["validator_set"] = {
        "epoch": 7,
        "active_set": ["@leader", "@helper-a", "@helper-b"],
    }
    state["consensus"] = consensus
    _write_state(ex, state)


def _quarantined_state(*helper_ids: str) -> dict[str, dict[str, Any]]:
    return {
        helper_id: {
            "helper_id": helper_id,
            "audits_total": 1,
            "success_count": 0,
            "fraud_count": 1,
            "timeout_count": 0,
            "quarantine_until_ms": 9_999_999_999_999,
            "last_event_ms": 1,
            "last_reason": "test_quarantine",
        }
        for helper_id in helper_ids
    }


def _submit_content_tx(ex: WeAllExecutor, *, body: str = "batch 601 helper root") -> None:
    out = ex.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {"body": body, "visibility": "public", "tags": [], "media": []},
        }
    )
    assert out["ok"] is True


def _build_helper_block(ex: WeAllExecutor) -> dict[str, Any]:
    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    assert len(applied_ids) == 1
    assert invalid_ids == []
    helper_execution = block.get("helper_execution")
    assert isinstance(helper_execution, dict)
    assert helper_execution.get("enabled") is True
    return helper_execution


def _plan_projection(helper_execution: dict[str, Any]) -> dict[str, Any]:
    lanes = helper_execution.get("lanes")
    assert isinstance(lanes, list)
    return {
        "plan_id": helper_execution.get("plan_id"),
        "source": (helper_execution.get("helper_planning_inputs") or {}).get("source"),
        "lanes": [
            {
                "lane_id": str(lane.get("lane_id") or ""),
                "helper_id": str(lane.get("helper_id") or ""),
                "tx_ids": list(lane.get("tx_ids") or []),
                "routing_mode": str(lane.get("routing_mode") or ""),
                "descriptor_hash": str(lane.get("descriptor_hash") or ""),
            }
            for lane in lanes
            if isinstance(lane, dict)
        ],
    }


def test_batch601_helper_planning_ignores_state_root_excluded_meta(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    chain_id = "batch601-helper-root-inputs"
    clean = _new_executor(tmp_path, "clean", chain_id=chain_id)
    noisy = _new_executor(tmp_path, "noisy", chain_id=chain_id)
    _bootstrap_helper_state(clean)
    _bootstrap_helper_state(noisy)

    noisy_state = dict(noisy.state)
    noisy_state["meta"] = {
        "helper_reputation": _quarantined_state("@helper-a", "@helper-b"),
        "helper_capacity_by_helper": {"@helper-a": 0, "@helper-b": 0},
        "helper_capabilities_by_helper": {
            "@helper-a": {"lane_classes": []},
            "@helper-b": {"lane_classes": []},
        },
    }
    _write_state(noisy, noisy_state)

    assert compute_state_root(clean.state) == compute_state_root(noisy.state)

    _submit_content_tx(clean)
    _submit_content_tx(noisy)

    clean_plan = _plan_projection(_build_helper_block(clean))
    noisy_plan = _plan_projection(_build_helper_block(noisy))

    assert clean_plan == noisy_plan
    assert clean_plan["source"] == "state_root"
    assert any(lane["helper_id"] in {"@helper-a", "@helper-b"} for lane in clean_plan["lanes"])


def test_batch601_root_committed_helper_reputation_controls_quarantine(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    ex = _new_executor(tmp_path, "rooted", chain_id="batch601-rooted-quarantine")
    _bootstrap_helper_state(ex)
    state = dict(ex.state)
    state["helper_reputation"] = _quarantined_state("@helper-a", "@helper-b")
    # This conflicting meta should be ignored; the root-visible helper_reputation
    # above is the only consensus-relevant quarantine input.
    state["meta"] = {"helper_reputation": {}}
    _write_state(ex, state)

    _submit_content_tx(ex)
    helper_execution = _build_helper_block(ex)

    planning_inputs = helper_execution.get("helper_planning_inputs")
    assert isinstance(planning_inputs, dict)
    assert planning_inputs == {
        "source": "state_root",
        "state_root_keys": [
            "helper_reputation",
            "helper_capacity_by_helper",
            "helper_capabilities_by_helper",
        ],
        "meta_ignored_for_consensus": True,
    }

    lanes = helper_execution.get("lanes")
    assert isinstance(lanes, list) and lanes
    # All eligible non-leader helpers are quarantined by root-visible state, so
    # the lane must deterministically fall back to serial/no-helper execution.
    assert all(str(lane.get("helper_id") or "") == "" for lane in lanes if isinstance(lane, dict))
    summary = helper_execution.get("helper_reputation")
    assert isinstance(summary, dict)
    assert summary.get("quarantined_helper_ids") == ["@helper-a", "@helper-b"]
