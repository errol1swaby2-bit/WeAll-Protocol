from __future__ import annotations

from pathlib import Path

from weall.net.peer_list_store import PeerListStore


def test_peer_list_store_load_save_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "peers.txt"
    store = PeerListStore(path=str(p), max_peers=5, min_write_interval_ms=0)

    store.save(["tcp://1.1.1.1:30303", "tls://node.example:30303", "tcp://1.1.1.1:30303"], force=True)
    got = store.load()
    assert got == ["tcp://1.1.1.1:30303", "tls://node.example:30303"]


def test_peer_list_store_ignores_invalid_lines(tmp_path: Path) -> None:
    p = tmp_path / "peers.txt"
    p.write_text(
        """
        # comment

        http://bad
        tcp://2.2.2.2:30303
        tls://ok.example:30303
        nonsense
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    store = PeerListStore(path=str(p), max_peers=100, min_write_interval_ms=0)
    assert store.load() == ["tcp://2.2.2.2:30303", "tls://ok.example:30303"]


def test_peer_list_store_caps_max_peers(tmp_path: Path) -> None:
    p = tmp_path / "peers.txt"
    store = PeerListStore(path=str(p), max_peers=3, min_write_interval_ms=0)
    store.save(
        [
            "tcp://1.1.1.1:1",
            "tcp://1.1.1.1:2",
            "tcp://1.1.1.1:3",
            "tcp://1.1.1.1:4",
        ],
        force=True,
    )
    assert store.load() == ["tcp://1.1.1.1:1", "tcp://1.1.1.1:2", "tcp://1.1.1.1:3"]
