# src/weall/net/transport_memory.py
"""
WeAll Protocol — In-Memory Transport (Test / Local Harness)

This backend implements the same Transport/Connection interface as the real
TCP/TLS transports, but keeps all packets in-process.

Design goals:
  - Deterministic + easy to reason about in tests
  - No sockets, no threads
  - Compatible with weall.net.transport.{Transport,Connection,WirePacket,PeerAddr}

Addressing:
  - Use PeerAddr("mem://<name>") as the bind/connect uri.
  - bind() registers this transport instance under that uri.
  - connect() returns a Connection to the remote transport (by uri).
  - send() enqueues a WirePacket into the remote transport inbox, with peer_id
    set to the sender's bound uri (or "mem://anonymous" if unbound).

This is intentionally minimal and should never be used for production networking.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

from weall.net.transport import Connection, PeerAddr, WirePacket


def _now_ms() -> int:
    return int(time.time() * 1000)


# Global registry so multiple InMemoryTransport instances can connect.
_REGISTRY: dict[str, InMemoryTransport] = {}


@dataclass(slots=True)
class _MemConn(Connection):
    _peer_id: str
    _peer_addr: PeerAddr
    _local: InMemoryTransport
    _remote: InMemoryTransport
    _closed: bool = False

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def peer_addr(self) -> PeerAddr:
        return self._peer_addr

    def send(self, payload: bytes) -> None:
        if self._closed:
            return
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        sender = self._local.bound_uri or "mem://anonymous"
        # Remote receives packet "from" the sender's uri.
        self._remote._inbox.append(
            WirePacket(
                peer_id=str(sender),
                payload=bytes(payload),
                received_at_ms=_now_ms(),
                meta={"transport": "mem"},
            )
        )

    def close(self) -> None:
        self._closed = True


class InMemoryTransport:
    """
    In-process Transport implementation.

    Implements:
      - bind(PeerAddr)
      - connect(PeerAddr) -> Connection
      - poll(max_packets) -> Iterable[WirePacket]
      - connections() -> Iterable[Connection]
      - close()
    """

    def __init__(self) -> None:
        self.bound_uri: str = ""
        self._closed: bool = False
        self._inbox: list[WirePacket] = []
        self._conns: dict[str, _MemConn] = {}

    def bind(self, addr: PeerAddr) -> None:
        if self._closed:
            raise RuntimeError("transport closed")
        uri = str(getattr(addr, "uri", "") or "").strip()
        if not uri:
            raise ValueError("PeerAddr.uri required")
        self.bound_uri = uri
        _REGISTRY[uri] = self

    def connect(self, addr: PeerAddr) -> Connection:
        if self._closed:
            raise RuntimeError("transport closed")
        uri = str(getattr(addr, "uri", "") or "").strip()
        if not uri:
            raise ValueError("PeerAddr.uri required")
        remote = _REGISTRY.get(uri)
        if remote is None:
            raise ConnectionError(f"mem transport target not bound: {uri}")
        peer_id = uri  # stable transport-level id for that peer
        existing = self._conns.get(peer_id)
        if existing is not None:
            return existing
        c = _MemConn(_peer_id=peer_id, _peer_addr=PeerAddr(uri=uri), _local=self, _remote=remote)
        self._conns[peer_id] = c
        return c

    def poll(self, *, max_packets: int = 250) -> Iterable[WirePacket]:
        if self._closed:
            return []
        n = int(max_packets) if int(max_packets) > 0 else 250
        out = self._inbox[:n]
        del self._inbox[:n]
        return out

    def connections(self) -> Iterable[Connection]:
        return list(self._conns.values())

    def close(self) -> None:
        self._closed = True
        if self.bound_uri and _REGISTRY.get(self.bound_uri) is self:
            _REGISTRY.pop(self.bound_uri, None)
        self._inbox.clear()
        for c in list(self._conns.values()):
            try:
                c.close()
            except Exception:
                pass
        self._conns.clear()

    # ---- helpers for tests/harness ----

    def _inject(self, *, peer_id: str, payload: bytes, received_at_ms: int | None = None) -> None:
        """Inject a packet into this transport's inbox."""
        if self._closed:
            return
        self._inbox.append(
            WirePacket(
                peer_id=str(peer_id),
                payload=bytes(payload),
                received_at_ms=int(received_at_ms) if received_at_ms is not None else _now_ms(),
                meta={"transport": "mem", "injected": "1"},
            )
        )
