from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.runtime.helper_block_validation import validate_received_helper_execution


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "recursive-sync") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_register_block(ex: WeAllExecutor, signer: str) -> None:
    sub = ex.submit_tx({
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": {"pubkey": f"k:{signer}"},
    })
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


class _SyncPeer:
    def __init__(self, source: WeAllExecutor) -> None:
        self.source = source

    def request_state_sync(self, _peer_id, req, **_kwargs):
        return self.source._state_sync_service().handle_request(req)


def test_pruned_delta_falls_back_to_restartable_checkpoint_snapshot(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")
    for i in range(1, 5):
        _produce_register_block(leader, f"@u{i}")

    result = leader._db.prune_history(
        retain_last_blocks=1, retain_blocks_ms=0, retain_bft_candidates_ms=0
    )
    assert int(result["deleted_blocks"]) >= 1
    assert leader.get_block_by_height(1) is None
    assert leader.get_block_by_height(4) is not None

    anchor = build_snapshot_anchor(leader.state)
    metas = lagger.request_and_apply_state_sync(
        _SyncPeer(leader), "leader", trusted_anchor=anchor, timeout_ms=100, sleep_ms=0
    )
    assert metas == []
    assert build_snapshot_anchor(lagger.state) == anchor
    assert lagger.get_block_by_height(4) is not None
    assert lagger.get_block_by_height(1) is None

    restarted = _make_executor(tmp_path, "lagger")
    restarted_anchor = build_snapshot_anchor(restarted.state)
    for key in ("height", "tip_hash", "state_root", "finalized_height", "finalized_block_id"):
        assert restarted_anchor[key] == anchor[key]
    assert restarted.get_block_by_height(4) is not None


def test_nonempty_lagger_can_advance_to_fully_pinned_checkpoint_snapshot(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")
    _produce_register_block(lagger, "@local")
    for i in range(1, 5):
        _produce_register_block(leader, f"@u{i}")
    leader._db.prune_history(retain_last_blocks=1, retain_blocks_ms=0, retain_bft_candidates_ms=0)

    anchor = build_snapshot_anchor(leader.state)
    lagger.request_and_apply_state_sync(
        _SyncPeer(leader), "leader", trusted_anchor=anchor, timeout_ms=100, sleep_ms=0
    )
    assert build_snapshot_anchor(lagger.state) == anchor
    assert lagger.get_block_by_height(int(anchor["height"])) is not None


def test_snapshot_checkpoint_mismatch_is_rejected(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")
    _produce_register_block(leader, "@u1")
    service = leader._state_sync_service()
    anchor = build_snapshot_anchor(leader.state)
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id=leader.chain_id,
            schema_version="1",
            tx_index_hash=leader._tx_index_hash,
            sent_ts_ms=0,
            corr_id="checkpoint",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )
    resp = service.handle_request(req)
    bad_block = copy.deepcopy(resp.blocks[0])
    bad_block["height"] = 99
    bad = StateSyncResponseMsg(
        header=resp.header, ok=True, reason=resp.reason, height=resp.height,
        snapshot=resp.snapshot, snapshot_hash=resp.snapshot_hash,
        snapshot_anchor=resp.snapshot_anchor, blocks=(bad_block,),
    )
    with pytest.raises(ExecutorError, match="state_sync_verify_failed:snapshot_checkpoint_height_mismatch"):
        lagger.apply_state_sync_response(
            bad, trusted_anchor=anchor, allow_snapshot_bootstrap=True
        )


def test_restart_rebinds_wrong_nonzero_tip_timestamp_to_persisted_tip(tmp_path: Path) -> None:
    ex = _make_executor(tmp_path, "node")
    _produce_register_block(ex, "@u1")
    tip = ex.get_block_by_height(1)
    assert isinstance(tip, dict)
    expected_ts = int(tip.get("block_ts_ms") or 0)
    assert expected_ts > 0

    with ex._db.write_tx() as con:
        row = con.execute("SELECT state_json FROM ledger_state WHERE id=1").fetchone()
        state = json.loads(row["state_json"])
        state["tip_ts_ms"] = expected_ts + 999999
        con.execute(
            "UPDATE ledger_state SET state_json=? WHERE id=1",
            (json.dumps(state, sort_keys=True, separators=(",", ":")),),
        )

    restarted = _make_executor(tmp_path, "node")
    assert int(restarted.state.get("tip_ts_ms") or 0) == expected_ts


def test_authority_map_covers_declared_consensus_execution_recovery_set() -> None:
    obj = json.loads((_repo_root() / "configs/authoritative_mechanism_map.json").read_text())
    required = set(obj["required_high_risk_mechanisms"])
    mapped = set(obj["mechanisms"])
    assert len(required) >= 18
    assert required <= mapped
    assert {"M-010", "M-011", "M-012", "M-015", "M-016", "M-018", "M-021"} <= required
    assert "src/weall/runtime/block_signature_profiles.py" in obj["mechanisms"]["M-018"]["forbidden_shadow_paths"]


def test_helper_receive_rejects_self_consistent_noncanonical_plan() -> None:
    state = {
        "helper_reputation": {},
        "helper_capacity_by_helper": {},
        "helper_capabilities_by_helper": {},
    }
    block = {
        "height": 2, "view": 3, "proposer": "@v1", "block_ts_ms": 1000,
        "txs": [{"tx_id": "t1", "tx_type": "ACCOUNT_REGISTER", "signer": "@u", "nonce": 1, "payload": {}}],
    }
    from weall.runtime.parallel_execution import (
        plan_parallel_execution, canonical_helper_execution_plan_fingerprint
    )
    local = plan_parallel_execution(
        txs=block["txs"], validators=["@v1", "@v2"], validator_set_hash="set",
        view=3, leader_id="@v1", state_snapshot_metadata={
            "validator_epoch": 1, "quarantined_helper_ids": [],
            "helper_capacity_by_helper": {}, "helper_capabilities_by_helper": {},
            "helper_planning_inputs_source": "state_root", "allow_helper_overcommit": True,
        },
    )
    assert local
    lane = local[0]
    wrong_helper = "@v2" if str(lane.helper_id or "") != "@v2" else "@v1"
    remote_lanes = [{
        "lane_id": lane.lane_id, "helper_id": wrong_helper,
        "tx_ids": list(lane.tx_ids), "descriptor_hash": lane.descriptor_hash,
    }]
    remote_plan_id = canonical_helper_execution_plan_fingerprint(remote_lanes)
    for row in remote_lanes:
        row["plan_id"] = remote_plan_id
    block["helper_execution"] = {
        "plan_id": remote_plan_id, "view": 3, "validator_epoch": 1,
        "validator_set_hash": "set", "coordinator_id": "@v1",
        "lanes": remote_lanes, "accepted_certificates": [],
        "helper_reputation": {"transition_policy": "diagnostic_only_v1", "state_committed": False},
    }
    ok, reason = validate_received_helper_execution(
        block=block, state=state, chain_id="chain", validators=["@v1", "@v2"],
        validator_pubkeys={}, validator_epoch=1, validator_set_hash="set"
    )
    assert ok is False
    assert reason == "helper_execution_canonical_plan_mismatch"


def test_snapshot_checkpoint_may_be_newer_than_finalized_height_when_fully_pinned() -> None:
    from weall.runtime.block_hash import compute_block_hash
    from weall.runtime.state_hash import compute_state_root

    snapshot = {
        "height": 5,
        "tip": "b5",
        "tip_hash": "",
        "finalized": {"height": 3, "block_id": "b3"},
    }
    root = compute_state_root(snapshot)
    header = {"height": 5, "state_root": root}
    checkpoint = {
        "height": 5,
        "block_id": "b5",
        "header": header,
    }
    snapshot["tip_hash"] = compute_block_hash(header=header)
    anchor = build_snapshot_anchor(snapshot)

    service = StateSyncService(
        chain_id="c1",
        schema_version="1",
        tx_index_hash="txhash",
        state_provider=lambda: dict(snapshot),
        block_provider=lambda h: dict(checkpoint) if int(h) == 5 else None,
        bft_enabled=True,
    )
    service.enforce_finalized_anchor = True
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="c1",
            schema_version="1",
            tx_index_hash="txhash",
            sent_ts_ms=0,
            corr_id="checkpoint-finality-gap",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )

    resp = service.handle_request(req)
    assert resp.ok is True
    assert len(resp.blocks) == 1
    assert int(resp.blocks[0]["height"]) == 5
    assert int(anchor["finalized_height"]) == 3
    service.verify_response(resp, trusted_anchor=anchor)
