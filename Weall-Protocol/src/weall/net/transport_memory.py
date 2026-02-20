from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(slots=True)
class Packet:
    peer_id: str
    payload: bytes


class _Conn:
    def __init__(self, *, peer_id: str) -> None:
        self.peer_id = peer_id
        self._out: List[bytes] = []

    def send(self, payload: bytes) -> None:
        self._out.append(payload)

    def drain(self) -> List[bytes]:
        out = list(self._out)
        self._out.clear()
        return out


class InMemoryTransport:
    """
    Minimal in-process transport used for unit tests.

    - Does not open sockets
    - Does not perform TLS
    - Provides the same surface NetNode expects:
        bind(), stop(), tick(), recv(), connections()
    """

    def __init__(self) -> None:
        self._inbox: List[Packet] = []
        self._conns: dict[str, _Conn] = {}
        self._bound = False

    def bind(self, host: str, port: int) -> None:
        self._bound = True

    def stop(self) -> None:
        self._bound = False
        self._inbox.clear()
        self._conns.clear()

    def tick(self) -> None:
        # no-op
        return

    def recv(self) -> List[Packet]:
        out = list(self._inbox)
        self._inbox.clear()
        return out

    def connections(self) -> List[_Conn]:
        return list(self._conns.values())

    # ---- helpers for tests / harness ----

    def _ensure_conn(self, peer_id: str) -> _Conn:
        c = self._conns.get(peer_id)
        if c is None:
            c = _Conn(peer_id=peer_id)
            self._conns[peer_id] = c
        return c

    def _inject(self, *, peer_id: str, payload: bytes) -> None:
        self._ensure_conn(peer_id)
        self._inbox.append(Packet(peer_id=peer_id, payload=payload))
