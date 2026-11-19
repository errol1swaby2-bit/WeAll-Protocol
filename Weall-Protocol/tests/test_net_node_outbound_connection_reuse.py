from __future__ import annotations

from weall.net.node import NetConfig, NetNode
from weall.net.transport import PeerAddr


class _Connection:
    def __init__(self, addr: PeerAddr) -> None:
        self.peer_id = addr.uri
        self.peer_addr = addr
        self.closed = False
        self.inbound = False
        self.sent: list[bytes] = []

    def send(self, payload: bytes) -> None:
        self.sent.append(bytes(payload))

    def close(self) -> None:
        self.closed = True


class _Transport:
    def __init__(self) -> None:
        self.calls = 0
        self.current: list[_Connection] = []

    def connect(self, addr: PeerAddr) -> _Connection:
        self.calls += 1
        conn = _Connection(addr)
        self.current.append(conn)
        return conn

    def connections(self) -> list[_Connection]:
        return list(self.current)

    def close(self) -> None:
        for conn in self.current:
            conn.close()


def test_outbound_peer_connection_is_reused_until_closed(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "0")
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    transport = _Transport()
    node = NetNode(
        cfg=NetConfig(
            chain_id="dial-dedupe-test",
            schema_version="1",
            tx_index_hash="deadbeef",
            peer_id="local",
        ),
        transport=transport,
    )
    addr = PeerAddr(uri="tcp://127.0.0.1:30303")
    first = node.connect(addr)
    assert transport.calls == 1
    assert len(first.sent) == 1

    for _ in range(20):
        assert node.connect(addr) is first
    assert transport.calls == 1
    assert len(first.sent) == 1

    first.close()
    second = node.connect(addr)
    assert second is not first
    assert transport.calls == 2
    assert len(second.sent) == 1
    node.close()
