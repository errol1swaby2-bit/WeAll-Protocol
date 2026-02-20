"""
WeAll Protocol — Network Transport (Abstract I/O Layer)

Goal:
  Provide a minimal, stable abstraction for peer I/O so the rest of the stack
  (codec/router/handshake/gossip) stays pure and testable.

Notes:
  - "wire" bytes are canonical JSON produced by weall.net.codec.encode_message()
  - Transport is responsible for:
      * accepting/initiating connections
      * framing (turning byte streams into discrete packets)
      * providing poll() to the node loop

This module is pure structure: no sockets here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------

PeerId = str  # transport/session identifier for a connection (stable for that connection)


@dataclass(frozen=True, slots=True)
class PeerAddr:
    """
    Opaque addressing. Keep it stringly-typed to allow multiple backends.

    Examples:
      - "tcp://1.2.3.4:7777"
      - "ws://example.com/weall"
      - "quic://node.example:443"
      - "mem://peerA"
    """
    uri: str


@dataclass(frozen=True, slots=True)
class WirePacket:
    """
    Transport-level packet wrapper.

    - payload is a single framed message (canonical JSON bytes).
    - received_at_ms is optional (transport can fill it).
    - meta can store backend-specific details (remote ip, conn id, etc.)
    """
    peer_id: PeerId
    payload: bytes
    received_at_ms: Optional[int] = None
    meta: Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------
# Connection interface
# ---------------------------------------------------------------------

@runtime_checkable
class Connection(Protocol):
    """
    A live connection to a single peer.
    """

    @property
    def peer_id(self) -> PeerId: ...

    @property
    def peer_addr(self) -> PeerAddr: ...

    def send(self, payload: bytes) -> None: ...
    def close(self) -> None: ...


# ---------------------------------------------------------------------
# Transport interface
# ---------------------------------------------------------------------

@runtime_checkable
class Transport(Protocol):
    """
    A transport backend manages connections + framing.

    Node loop calls poll() repeatedly to receive WirePackets.
    """

    def bind(self, addr: PeerAddr) -> None: ...
    def connect(self, addr: PeerAddr) -> Connection: ...

    def poll(self, *, max_packets: int = 250) -> Iterable[WirePacket]: ...

    def connections(self) -> Iterable[Connection]: ...

    def close(self) -> None: ...

