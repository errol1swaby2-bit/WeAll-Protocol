# src/weall/net/__init__.py
"""
WeAll Protocol — Network package

This package provides a minimal, production-oriented network layer:
  - messages: canonical wire schemas (dataclasses)
  - codec: deterministic JSON encoding/decoding + header compatibility checks
  - transport: abstract I/O interfaces
  - transport_tcp: concrete TCP length-prefixed transport
  - handshake: strict compatibility session gate
  - router: dispatch by message type + session enforcement
  - node: minimal node loop wiring all components together

Higher layers (gossip/sync/consensus) should depend on:
  - net.node (for running)
  - net.router (for message dispatch)
  - net.codec (for canonical encoding)
and should keep their own logic separate.
"""

from __future__ import annotations

__all__ = [
    "messages",
    "codec",
    "transport",
    "transport_tcp",
    "handshake",
    "router",
    "node",
]
