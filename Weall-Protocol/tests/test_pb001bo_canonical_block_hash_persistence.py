from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.block_commitment_validation import BlockCommitmentBindingError
from weall.runtime.block_hash import (
    BlockHashBindingError,
    compute_block_hash,
    ensure_canonical_block_hash,
)
from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.runtime.state_hash import compute_state_root


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, name: str, *, chain_id: str = "pb001bo") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_block(ex: WeAllExecutor, *, signer: str, nonce: int) -> dict:
    submitted = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert submitted["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    block = ex.get_block_by_height(int(ex.state["height"]))
    assert isinstance(block, dict)
    return block


def _snapshot_response(ex: WeAllExecutor):
    anchor = build_snapshot_anchor(ex.state)
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id=ex.chain_id,
            schema_version="1",
            tx_index_hash=ex._tx_index_hash,
            sent_ts_ms=0,
            corr_id="pb001bo-checkpoint",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )
    response = ex._state_sync_service().handle_request(req)
    assert response.snapshot is not None
    assert len(response.blocks or ()) == 1
    return response, anchor


def _tamper_checkpoint_header(response: StateSyncResponseMsg) -> tuple[StateSyncResponseMsg, str]:
    block = copy.deepcopy(response.blocks[0])
    advertised_hash = str(block["block_hash"])
    block["header"]["pb001bo_probe"] = "tampered"
    assert compute_block_hash(header=block["header"]) != advertised_hash
    bad = StateSyncResponseMsg(
        header=response.header,
        ok=True,
        reason=response.reason,
        height=response.height,
        snapshot=response.snapshot,
        snapshot_hash=response.snapshot_hash,
        snapshot_anchor=response.snapshot_anchor,
        blocks=(block,),
    )
    return bad, advertised_hash


def _replace_checkpoint(
    response: StateSyncResponseMsg,
    checkpoint: dict,
) -> StateSyncResponseMsg:
    return StateSyncResponseMsg(
        header=response.header,
        ok=True,
        reason=response.reason,
        height=response.height,
        snapshot=response.snapshot,
        snapshot_hash=response.snapshot_hash,
        snapshot_anchor=response.snapshot_anchor,
        blocks=(checkpoint,),
    )


def test_strict_hash_binding_rejects_advertised_header_mismatch() -> None:
    block = {
        "header": {
            "chain_id": "pb001bo",
            "height": 1,
            "prev_block_hash": "",
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "r",
        }
    }
    canonical = compute_block_hash(header=block["header"])
    block["block_hash"] = canonical
    bound, bound_hash = ensure_canonical_block_hash(copy.deepcopy(block))
    assert bound_hash == canonical
    assert bound["block_hash"] == canonical

    poisoned = copy.deepcopy(block)
    poisoned["header"]["block_ts_ms"] = 1001
    with pytest.raises(BlockHashBindingError, match="block_hash_mismatch"):
        ensure_canonical_block_hash(poisoned)


def test_state_sync_verifier_rejects_checkpoint_hash_alias(
    tmp_path: Path,
) -> None:
    leader = _executor(tmp_path, "leader")
    _produce_block(leader, signer="@u1", nonce=1)
    response, anchor = _snapshot_response(leader)
    bad, _advertised = _tamper_checkpoint_header(response)

    follower = _executor(tmp_path, "follower")
    with pytest.raises(StateSyncVerifyError, match="snapshot_checkpoint_hash_mismatch"):
        follower._state_sync_service().verify_response(bad, trusted_anchor=anchor)


def test_state_sync_apply_rejects_checkpoint_hash_alias_without_install(
    tmp_path: Path,
) -> None:
    leader = _executor(tmp_path, "leader")
    _produce_block(leader, signer="@u1", nonce=1)
    response, anchor = _snapshot_response(leader)
    bad, _advertised = _tamper_checkpoint_header(response)

    follower = _executor(tmp_path, "follower")
    with pytest.raises(
        ExecutorError, match="state_sync_verify_failed:snapshot_checkpoint_hash_mismatch"
    ):
        follower.apply_state_sync_response(
            bad,
            trusted_anchor=anchor,
            allow_snapshot_bootstrap=True,
        )
    assert int(follower.state.get("height") or 0) == 0


def test_checkpoint_store_defense_in_depth_rejects_hash_alias(
    tmp_path: Path,
) -> None:
    leader = _executor(tmp_path, "leader")
    _produce_block(leader, signer="@u1", nonce=1)
    response, _anchor = _snapshot_response(leader)
    bad, _advertised = _tamper_checkpoint_header(response)
    checkpoint = copy.deepcopy(bad.blocks[0])

    follower = _executor(tmp_path, "follower")
    with pytest.raises(BlockCommitmentBindingError, match="block_hash_mismatch"):
        follower._ledger_store.install_state_sync_checkpoint(
            state=dict(response.snapshot),
            checkpoint_block=checkpoint,
        )


def test_restart_fails_closed_when_persisted_tip_header_does_not_match_hash(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, "node")
    block = _produce_block(ex, signer="@u1", nonce=1)
    advertised_hash = str(block["block_hash"])

    with ex._db.write_tx() as con:
        row = con.execute("SELECT block_json FROM blocks WHERE height=1").fetchone()
        obj = json.loads(str(row["block_json"]))
        obj["header"]["pb001bo_probe"] = "tampered"
        assert compute_block_hash(header=obj["header"]) != advertised_hash
        con.execute(
            "UPDATE blocks SET block_json=? WHERE height=1",
            (json.dumps(obj, sort_keys=True, separators=(",", ":")),),
        )

    with pytest.raises(ExecutorError, match="db_invariant_violation"):
        _executor(tmp_path, "node")


def test_historical_persisted_block_read_fails_closed_on_hash_alias(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, "node")
    first = _produce_block(ex, signer="@u1", nonce=1)
    _produce_block(ex, signer="@u2", nonce=1)

    with ex._db.write_tx() as con:
        row = con.execute("SELECT block_json FROM blocks WHERE height=1").fetchone()
        obj = json.loads(str(row["block_json"]))
        obj["header"]["pb001bo_probe"] = "tampered"
        assert compute_block_hash(header=obj["header"]) != str(first["block_hash"])
        con.execute(
            "UPDATE blocks SET block_json=? WHERE height=1",
            (json.dumps(obj, sort_keys=True, separators=(",", ":")),),
        )

    restarted = _executor(tmp_path, "node")
    with pytest.raises(BlockCommitmentBindingError, match="block_hash_mismatch"):
        restarted.get_block_by_height(1)


def test_state_sync_verifier_rejects_checkpoint_block_id_alias(
    tmp_path: Path,
) -> None:
    leader = _executor(tmp_path, "leader", chain_id="pb001bo-id")
    _produce_block(leader, signer="@u1", nonce=1)
    response, anchor = _snapshot_response(leader)
    block = copy.deepcopy(response.blocks[0])
    block["prev_block_id"] = "forged-parent"
    bad = StateSyncResponseMsg(
        header=response.header,
        ok=True,
        reason=response.reason,
        height=response.height,
        snapshot=response.snapshot,
        snapshot_hash=response.snapshot_hash,
        snapshot_anchor=response.snapshot_anchor,
        blocks=(block,),
    )

    follower = _executor(tmp_path, "follower", chain_id="pb001bo-id")
    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_checkpoint_commitment_invalid:block_id_mismatch",
    ):
        follower._state_sync_service().verify_response(bad, trusted_anchor=anchor)


def test_state_sync_verifier_rejects_checkpoint_body_tx_alias(
    tmp_path: Path,
) -> None:
    leader = _executor(tmp_path, "leader", chain_id="pb001bo-body")
    _produce_block(leader, signer="@u1", nonce=1)
    response, anchor = _snapshot_response(leader)
    block = copy.deepcopy(response.blocks[0])
    assert isinstance(block.get("txs"), list) and block["txs"]
    block["txs"][0]["payload"]["pubkey"] = "forged-pubkey"
    bad = StateSyncResponseMsg(
        header=response.header,
        ok=True,
        reason=response.reason,
        height=response.height,
        snapshot=response.snapshot,
        snapshot_hash=response.snapshot_hash,
        snapshot_anchor=response.snapshot_anchor,
        blocks=(block,),
    )

    follower = _executor(tmp_path, "follower", chain_id="pb001bo-body")
    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_checkpoint_commitment_invalid:body_tx_id_mismatch:0",
    ):
        follower._state_sync_service().verify_response(bad, trusted_anchor=anchor)


def test_prod_state_sync_rejects_minimal_checkpoint_compat_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    snapshot = {
        "height": 5,
        "tip": "b5",
        "tip_hash": "",
        "finalized": {"height": 3, "block_id": "b3"},
    }
    root = compute_state_root(snapshot)
    header = {"height": 5, "state_root": root}
    checkpoint = {"height": 5, "block_id": "b5", "header": header}
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
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id="c1",
            schema_version="1",
            tx_index_hash="txhash",
            sent_ts_ms=0,
            corr_id="pb001bo-prod-minimal",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )
    resp = service.handle_request(req)
    assert resp.ok is True
    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_checkpoint_commitment_invalid:chain_id_mismatch",
    ):
        service.verify_response(resp, trusted_anchor=anchor)


def test_state_sync_verifier_rejects_checkpoint_receipt_body_alias(tmp_path: Path) -> None:
    leader = _executor(tmp_path, "receipt-leader")
    _produce_block(leader, signer="@alice", nonce=1)
    resp, anchor = _snapshot_response(leader)
    service = leader._state_sync_service()
    forged = copy.deepcopy(resp.blocks[0])
    assert isinstance(forged.get("receipts"), list) and forged["receipts"]
    forged["receipts"][0]["signer"] = "@forged"
    bad = _replace_checkpoint(resp, forged)
    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_checkpoint_commitment_invalid:receipts_root_mismatch",
    ):
        service.verify_response(bad, trusted_anchor=anchor)


def test_state_sync_verifier_rejects_uncommitted_helper_execution_alias(
    tmp_path: Path,
) -> None:
    leader = _executor(tmp_path, "helper-leader")
    _produce_block(leader, signer="@alice", nonce=1)
    resp, anchor = _snapshot_response(leader)
    service = leader._state_sync_service()
    forged = copy.deepcopy(resp.blocks[0])
    assert not str(forged["header"].get("helper_execution_root") or "")
    forged["helper_execution"] = {"plan_id": "forged", "lanes": []}
    bad = _replace_checkpoint(resp, forged)
    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_checkpoint_commitment_invalid:unexpected_helper_execution",
    ):
        service.verify_response(bad, trusted_anchor=anchor)
