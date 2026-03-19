from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from weall.net.net_loop import (
    NetLoopConfig,
    NetMeshLoop,
    NetPeerConfigError,
    NetStartupError,
)
from weall.runtime.executor import WeAllExecutor


class _DummyMempool:
    pass


class _FakeNode:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(peer_id="local-peer", chain_id="chain-A", schema_version="1", tx_index_hash="deadbeef")

    def connect(self, addr) -> None:
        return None


class _SimpleExecutor:
    chain_id = "chain-A"
    tx_index = None

    def snapshot(self):
        return {}


class _BrokenPeerStore:
    def read_list(self):
        raise RuntimeError("peer list unreadable")


class _BadTypePeerStore:
    def read_list(self):
        return [{"uri": "tcp://peer-a:30303"}]


class _BadUriPeerStore:
    def read_list(self):
        return ["http://peer-a.example"]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="failclosed-batch8",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def test_init_raises_in_prod_when_env_peer_merge_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PEERS_FILE", str(tmp_path / "peers.txt"))
    monkeypatch.setenv("WEALL_PEERS", "tcp://peer-a:30303")

    def _boom(self, peers, *, force=False):
        raise RuntimeError("merge failed")

    monkeypatch.setattr("weall.net.peer_list_store.PeerListStore.merge", _boom)

    ex = _make_executor(tmp_path, "env-merge-fail")
    with pytest.raises(NetStartupError, match="net_env_peer_merge_failed"):
        NetMeshLoop(
            executor=ex,
            mempool=ex._mempool,
            cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="1"),
        )


def test_dial_peers_tick_raises_in_prod_when_peer_list_read_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_SimpleExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode()
    loop._peers_store = _BrokenPeerStore()

    with pytest.raises(NetPeerConfigError, match="peer_list_read_failed"):
        loop._dial_peers_tick()


def test_dial_peers_tick_raises_in_prod_when_peer_list_entry_type_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_SimpleExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode()
    loop._peers_store = _BadTypePeerStore()

    with pytest.raises(NetPeerConfigError, match="peer_list_entry_invalid_type"):
        loop._dial_peers_tick()


def test_dial_peers_tick_raises_in_prod_when_peer_list_entry_uri_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_SimpleExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = _FakeNode()
    loop._peers_store = _BadUriPeerStore()

    with pytest.raises(NetPeerConfigError, match="peer_list_entry_invalid_uri"):
        loop._dial_peers_tick()
