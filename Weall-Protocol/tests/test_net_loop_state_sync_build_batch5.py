from __future__ import annotations

from pathlib import Path

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "batch5-live") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_register_block(ex: WeAllExecutor, signer: str, nonce: int) -> None:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


def _req(
    ex: WeAllExecutor,
    corr_id: str,
    *,
    mode: str,
    from_height: int = 0,
    to_height: int | None = None,
    selector=None,
) -> StateSyncRequestMsg:
    return StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id=ex.chain_id,
            schema_version=ex._schema_version(),
            tx_index_hash=ex.tx_index_hash(),
            corr_id=corr_id,
        ),
        mode=mode,
        from_height=from_height,
        to_height=to_height,
        selector=selector,
    )


def test_net_loop_build_node_uses_executor_sync_metadata(tmp_path: Path) -> None:
    ex = _make_executor(tmp_path, "node-a", chain_id="sync-live")
    loop = NetMeshLoop(
        executor=ex,
        mempool=ex._mempool,
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="stale"
        ),
    )

    node = loop._build_node()

    assert node.cfg.chain_id == "sync-live"
    assert node.cfg.schema_version == ex._schema_version()
    assert node.cfg.tx_index_hash == ex.tx_index_hash()
    assert node.sync_service is not None
    assert node.sync_service.chain_id == ex.chain_id
    assert node.sync_service.schema_version == ex._schema_version()
    assert node.sync_service.tx_index_hash == ex.tx_index_hash()


def test_net_loop_built_sync_service_serves_snapshot_and_delta(tmp_path: Path) -> None:
    ex = _make_executor(tmp_path, "leader", chain_id="sync-live")
    _produce_register_block(ex, "@u1", 1)
    _produce_register_block(ex, "@u2", 1)

    loop = NetMeshLoop(
        executor=ex,
        mempool=ex._mempool,
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="bad"
        ),
    )
    node = loop._build_node()
    assert node.sync_service is not None

    snap_req = _req(ex, "snap-1", mode="snapshot")
    snap_resp = node.sync_service.handle_request(snap_req)
    assert snap_resp.ok is True
    assert isinstance(snap_resp.snapshot, dict)
    assert int(snap_resp.snapshot.get("height") or 0) == 2

    anchor = build_snapshot_anchor(ex.state)
    delta_req = _req(
        ex, "delta-1", mode="delta", from_height=0, to_height=2, selector={"trusted_anchor": anchor}
    )
    delta_resp = node.sync_service.handle_request(delta_req)
    assert delta_resp.ok is True
    assert [int(b.get("height") or 0) for b in delta_resp.blocks] == [1, 2]
