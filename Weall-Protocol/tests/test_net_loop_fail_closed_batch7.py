from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.net_loop import (
    NetLoopConfig,
    NetMeshLoop,
    NetStartupError,
    NetStateSnapshotError,
)
from weall.runtime.executor import WeAllExecutor


class _BadSnapshotExecutor:
    def __init__(self) -> None:
        self.chain_id = "failclosed-batch7"

    def snapshot(self):
        raise RuntimeError("boom")


class _InvalidSnapshotExecutor:
    def __init__(self) -> None:
        self.chain_id = "failclosed-batch7"

    def snapshot(self):
        return []


class _BrokenMetaExecutor:
    def __init__(self) -> None:
        self.chain_id = "failclosed-batch7"

    def _schema_version(self):
        return "1"

    def tx_index_hash(self):
        raise RuntimeError("tx index unavailable")

    def snapshot(self):
        return {}


class _DummyMempool:
    pass


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="failclosed-batch7",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def test_state_snapshot_raises_in_prod_when_executor_snapshot_throws(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_BadSnapshotExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="1"
        ),
    )

    with pytest.raises(NetStateSnapshotError, match="state_snapshot_failed"):
        loop._state_snapshot()


def test_state_snapshot_raises_in_prod_when_snapshot_is_not_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_InvalidSnapshotExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="1"
        ),
    )

    with pytest.raises(NetStateSnapshotError, match="state_snapshot_invalid_type"):
        loop._state_snapshot()


def test_build_node_raises_in_prod_when_tx_index_hash_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_BrokenMetaExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="1"
        ),
    )

    with pytest.raises(NetStartupError, match="net_build_node_tx_index_hash_failed"):
        loop._build_node()


def test_start_returns_false_in_prod_when_seed_discovery_throws(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _make_executor(tmp_path, "seed-fail")
    loop = NetMeshLoop(
        executor=ex,
        mempool=ex._mempool,
        cfg=NetLoopConfig(
            enabled=True, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="1"
        ),
    )

    def _boom() -> None:
        raise RuntimeError("seed discovery failed")

    monkeypatch.setattr(loop, "_seed_discover_once", _boom)

    assert loop.start() is False
    assert loop.node is None
