from __future__ import annotations

import copy
import json
from pathlib import Path

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.governance import apply_governance
from weall.runtime.block_admission import admit_bft_block
from weall.runtime.block_hash import compute_block_hash, compute_helper_execution_root
from weall.runtime.executor import WeAllExecutor
from weall.runtime.mempool import PersistentMempool
from weall.runtime.sqlite_db import SqliteDB
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _write_clock_manifest(path: Path, *, chain_id: str) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "chain_id": chain_id,
                "profile": "controlled_testnet",
                "mode": "dev",
                "schema_version": "test",
                "genesis_time_ms": 0,
                "constitutional_clock": {
                    "enabled": True,
                    "target_block_interval_ms": 20_000,
                    "empty_blocks_enabled": True,
                    "procedure_time_source": "finalized_block_height",
                    "block_time_derivation": "genesis_time_plus_height_times_interval",
                    "no_fast_forward": True,
                    "no_height_skip": True,
                    "allowed_clock_skew_ms": 2_000,
                    "genesis_time_ms": 0,
                },
            },
            sort_keys=True,
        )
    )


def _new_executor(tmp_path: Path, name: str, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=_tx_index_path(),
    )


def _bootstrap_helper_account(ex: WeAllExecutor, *, account_id: str = "@alice") -> None:
    st = dict(ex.state)
    accounts = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}
    accounts[account_id] = {
        "pubkeys": [f"k:{account_id}"],
        "nonce": 1,
        "poh_tier": 2,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    st["accounts"] = accounts
    consensus = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    consensus["validator_set"] = {"epoch": 7, "active_set": ["@leader", "@helper-a", "@helper-b"]}
    st["consensus"] = consensus
    ex._ledger_store.write_state_snapshot(st)  # type: ignore[attr-defined]
    ex.state = ex._ledger_store.read()  # type: ignore[attr-defined]


def test_batch598_apply_block_rejects_off_slot_constitutional_timestamp(tmp_path: Path, monkeypatch) -> None:
    chain_id = "batch598-clock"
    manifest_path = tmp_path / "clock-manifest.json"
    _write_clock_manifest(manifest_path, chain_id=chain_id)
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))

    leader = _new_executor(tmp_path, "leader", chain_id=chain_id)
    follower = _new_executor(tmp_path, "follower", chain_id=chain_id)

    block, new_state, applied_ids, invalid_ids, err = leader.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    assert block["header"]["block_ts_ms"] == 20_000

    ok = follower.apply_block(copy.deepcopy(block))
    assert ok.ok is True
    assert compute_state_root(follower.state) == block["header"]["state_root"]

    bad = copy.deepcopy(block)
    bad["block_ts_ms"] = 20_001
    bad["header"]["block_ts_ms"] = 20_001
    bad.pop("block_hash", None)

    rejected = _new_executor(tmp_path, "rejector", chain_id=chain_id).apply_block(bad)
    assert rejected.ok is False
    assert rejected.error == "bad_block:ts_not_constitutional_slot"


def test_batch598_bft_admission_rejects_off_slot_constitutional_timestamp(tmp_path: Path, monkeypatch) -> None:
    chain_id = "batch598-bft-clock"
    manifest_path = tmp_path / "clock-manifest.json"
    _write_clock_manifest(manifest_path, chain_id=chain_id)
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))

    block = {
        "block_id": "b1",
        "prev_block_id": "",
        "header": {
            "chain_id": chain_id,
            "height": 1,
            "prev_block_hash": "",
            "block_ts_ms": 20_001,
            "tx_ids": [],
            "receipts_root": "0" * 64,
        },
        "txs": [],
    }
    ok, reject = admit_bft_block(block=block, state={"chain_id": chain_id, "height": 0}, bft_enabled=True)
    assert ok is False
    assert reject is not None
    assert reject.code == "bft_block_time_not_constitutional_slot"


def test_batch598_helper_reputation_is_state_root_committed_and_replayed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    chain_id = "batch598-helper-root"
    leader = _new_executor(tmp_path / "leader", "leader", chain_id=chain_id)
    follower = _new_executor(tmp_path / "follower", "follower", chain_id=chain_id)
    _bootstrap_helper_account(leader)
    _bootstrap_helper_account(follower)

    assert leader.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {"body": "helper root", "visibility": "public", "tags": [], "media": []},
        }
    )["ok"] is True

    block, new_state, _applied_ids, _invalid_ids, err = leader.build_block_candidate(max_txs=1)
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    helper_execution = block.get("helper_execution")
    assert isinstance(helper_execution, dict)
    assert "helper_reputation" in new_state
    assert new_state["helper_reputation"] == helper_execution["helper_reputation"]["state"]
    assert compute_state_root(new_state) == block["header"]["state_root"]

    meta = follower.apply_block(copy.deepcopy(block))
    assert meta.ok is True
    assert follower.state.get("helper_reputation") == helper_execution["helper_reputation"]["state"]


def test_batch598_apply_block_rejects_helper_metadata_plan_mismatch(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    chain_id = "batch598-helper-replay"
    leader = _new_executor(tmp_path / "leader", "leader", chain_id=chain_id)
    follower = _new_executor(tmp_path / "follower", "follower", chain_id=chain_id)
    _bootstrap_helper_account(leader)
    _bootstrap_helper_account(follower)

    assert leader.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {"body": "helper replay", "visibility": "public", "tags": [], "media": []},
        }
    )["ok"] is True
    block, _new_state, _applied_ids, _invalid_ids, err = leader.build_block_candidate(max_txs=1)
    assert err == ""
    tampered = copy.deepcopy(block)
    helper_execution = tampered.get("helper_execution")
    assert isinstance(helper_execution, dict)
    lanes = helper_execution.get("lanes")
    assert isinstance(lanes, list) and lanes
    assert isinstance(lanes[0], dict)
    lanes[0]["plan_id"] = "bad-plan-id"
    tampered["header"]["helper_execution_root"] = compute_helper_execution_root(helper_execution=helper_execution)
    tampered.pop("block_hash", None)
    tampered["block_hash"] = compute_block_hash(header=tampered["header"])

    res = follower.apply_block(tampered)
    assert res.ok is False
    assert res.error.startswith("bad_block:helper_execution_metadata_invalid:")


def test_batch598_governance_execution_and_receipts_are_restart_idempotent() -> None:
    state = {
        "height": 20,
        "gov_proposals_by_id": {
            "gp-restart": {
                "proposal_id": "gp-restart",
                "stage": "tallied",
                "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_percent": 67}}],
                "tallies": [{"height": 19, "payload": {"passed": True}}],
            }
        },
        "system_queue": [],
    }
    env = TxEnvelope(
        tx_type="GOV_EXECUTE",
        signer="SYSTEM",
        nonce=0,
        payload={"proposal_id": "gp-restart"},
        system=True,
        parent="gp-restart",
    )
    out1 = apply_governance(state, env)
    out2 = apply_governance(state, env)
    assert out1 == {"applied": True, "proposal_id": "gp-restart"}
    assert out2 == {"applied": True, "proposal_id": "gp-restart", "deduped": True}
    assert len(state["gov_proposals_by_id"]["gp-restart"].get("executions", [])) == 1
    assert len(state.get("governance_execution_audit", [])) == 1

    receipt = TxEnvelope(
        tx_type="GOV_EXECUTION_RECEIPT",
        signer="SYSTEM",
        nonce=0,
        payload={"proposal_id": "gp-restart", "ok": True, "_system_queue_id": "q1"},
        system=True,
        parent="gp-restart",
    )
    r1 = apply_governance(state, receipt)
    r2 = apply_governance(state, receipt)
    assert r1 == {"applied": True, "deduped": False}
    assert r2 == {"applied": True, "deduped": True}
    assert len(state.get("gov_execution_receipts", [])) == 1


def test_batch598_dispute_final_receipt_is_idempotent_before_enforcement_replay() -> None:
    state = {
        "height": 10,
        "accounts": {"SYSTEM": {"nonce": 0}, "@target": {"nonce": 0, "restricted": False}},
        "disputes_by_id": {
            "d-restart": {
                "dispute_id": "d-restart",
                "stage": "appeal_window",
                "resolution": {
                    "summary": "restriction",
                    "actions": [
                        {
                            "tx_type": "ACCOUNT_RESTRICTION_SET",
                            "payload": {"account_id": "@target", "restriction": "posting_limited"},
                        }
                    ],
                },
            }
        },
    }
    env = TxEnvelope(
        tx_type="DISPUTE_FINAL_RECEIPT",
        signer="SYSTEM",
        nonce=0,
        payload={"dispute_id": "d-restart", "receipt_id": "final:d-restart"},
        system=True,
        parent="d-restart",
    )
    out1 = apply_dispute(state, env)
    out2 = apply_dispute(state, env)
    assert out1["applied"] == "DISPUTE_FINAL_RECEIPT"
    assert out2["deduped"] is True
    assert len(state.get("dispute_receipts", {})) == 1
    assert state["disputes_by_id"]["d-restart"]["stage"] == "finalized"
    assert state["accounts"]["@target"]["restricted"] is True


def test_batch598_mempool_fetch_for_block_is_restart_stable_with_pinned_time(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    db = SqliteDB(path=str(tmp_path / "mempool.db"))
    mp = PersistentMempool(db=db, chain_id="batch598-mempool")
    assert mp.add({"tx_type": "ACCOUNT_REGISTER", "signer": "@b", "nonce": 2, "payload": {}, "expires_ms": 10_000})["ok"]
    assert mp.add({"tx_type": "ACCOUNT_REGISTER", "signer": "@a", "nonce": 1, "payload": {}, "expires_ms": 10_000})["ok"]

    before = mp.fetch_for_block(limit=10, policy="canonical", now_ms=5_000)
    restarted = PersistentMempool(db=SqliteDB(path=str(tmp_path / "mempool.db")), chain_id="batch598-mempool")
    after = restarted.fetch_for_block(limit=10, policy="canonical", now_ms=5_000)
    assert [item["tx_id"] for item in before] == [item["tx_id"] for item in after]
    assert [item["signer"] for item in after] == ["@a", "@b"]
    assert restarted.fetch_for_block(limit=10, policy="canonical", now_ms=10_001) == []
