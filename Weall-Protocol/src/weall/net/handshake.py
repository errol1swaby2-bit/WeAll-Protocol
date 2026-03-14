# File: src/weall/net/handshake.py
"""
WeAll Protocol — Network Handshake

Purpose:
  - Establish compatibility between peers BEFORE any tx/block traffic
  - Enforce strict invariants:
      * chain_id must match
      * schema_version must match
      * tx_index_hash must match (derived from generated/tx_index.json)
  - Negotiate a session id for subsequent messages

Non-goals (expanded in this build):
  - No transport I/O here (caller sends/receives using transport + codec)

Peer identity (THIS BUILD):
  - Outbound PEER_HELLO may optionally include an identity object proving
    control of an Ed25519 public key.
  - The intended binding is: the same public key the user created/added at
    account creation (ACCOUNT_REGISTER / ACCOUNT_KEY_ADD).
  - Verification happens at the node layer (net/node.py) because it requires
    a ledger snapshot.

This module provides:
  - HandshakeState: per-peer handshake state machine
  - build_hello / build_hello_ack helpers
  - process_inbound_hello / process_inbound_ack
  - begin_outbound_handshake / require_established (compat helpers for router/tests)

Integration pattern:
  - On connect:
      send HELLO
      await HELLO_ACK
      if ok: mark session established
  - On inbound HELLO:
      validate compatibility
      reply HELLO_ACK
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from weall.net.messages import MsgType, PeerHello, PeerHelloAck, WireHeader

# codec is used by caller; handshake operates on decoded dataclasses.
from weall.tx.canon import CanonError


# ---------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------


class HandshakeError(RuntimeError):
    pass


class HandshakeRejected(HandshakeError):
    """Raised when a peer is incompatible or handshake is refused."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------
# Config / defaults
# ---------------------------------------------------------------------

DEFAULT_HANDSHAKE_TIMEOUT_S = 10.0


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_corr_id() -> str:
    return secrets.token_hex(16)


def _new_session_id() -> str:
    # Stable length, URL-safe-ish (hex).
    return secrets.token_hex(24)


def _default_agent() -> str:
    # Keep it short; no env leakage.
    return "weall-node"


def _validate_non_empty(s: Any, field: str) -> str:
    if not isinstance(s, str) or not s.strip():
        raise CanonError(f"{field} must be non-empty string")
    return s.strip()


# ---------------------------------------------------------------------
# Handshake state
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HandshakeConfig:
    chain_id: str
    schema_version: str
    tx_index_hash: str
    peer_id: str
    agent: str = "weall-node"
    caps: Tuple[str, ...] = ()

    # Optional peer identity signing material.
    # If identity_privkey is provided (and identity_pubkey), the outgoing HELLO
    # will include a signed identity object:
    #   {account, pubkey, sig_alg, sig}
    identity_pubkey: Optional[str] = None
    identity_privkey: Optional[str] = None

    # Production posture: if True, outbound HELLO MUST include a valid identity
    # object. Any signing failure is fail-closed.
    require_identity: bool = False


@dataclass(slots=True)
class HandshakeState:
    """Per-peer handshake state.

    Lifecycle:
      NEW -> SENT_HELLO -> ESTABLISHED
      or
      NEW -> GOT_HELLO -> ESTABLISHED
      or failure -> REJECTED
    """

    config: HandshakeConfig

    status: str = "NEW"  # NEW | SENT_HELLO | GOT_HELLO | ESTABLISHED | REJECTED
    session_id: Optional[str] = None
    last_error: Optional[str] = None

    # Correlation id used for our outbound hello (if any)
    outbound_corr_id: Optional[str] = None

    # When handshake started (ms)
    started_ms: int = 0

    def start(self) -> None:
        self.started_ms = _now_ms()
        self.status = "NEW"
        self.session_id = None
        self.last_error = None
        self.outbound_corr_id = None

    def is_established(self) -> bool:
        return self.status == "ESTABLISHED" and bool(self.session_id)

    def is_timed_out(self, timeout_s: float = DEFAULT_HANDSHAKE_TIMEOUT_S) -> bool:
        if self.started_ms <= 0:
            return False
        return (_now_ms() - self.started_ms) > int(timeout_s * 1000)


# ---------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------


def build_hello(cfg: HandshakeConfig) -> PeerHello:
    """Create an outbound HELLO message."""

    chain_id = _validate_non_empty(cfg.chain_id, "chain_id")
    schema_version = _validate_non_empty(cfg.schema_version, "schema_version")
    tx_index_hash = _validate_non_empty(cfg.tx_index_hash, "tx_index_hash")
    peer_id = _validate_non_empty(cfg.peer_id, "peer_id")

    corr_id = _new_corr_id()
    hdr = WireHeader(
        type=MsgType.PEER_HELLO,
        chain_id=chain_id,
        schema_version=schema_version,
        tx_index_hash=tx_index_hash,
        sent_ts_ms=_now_ms(),
        corr_id=corr_id,
    )

    # Nonce is signed (when identity is present) and provides replay resistance.
    # Use corr_id for stable linkage and to avoid extra randomness calls.
    hello_nonce = corr_id

    # Optional: include a signed identity binding using the user's account pubkey.
    identity: Optional[Dict[str, Any]] = None
    pubkey = (cfg.identity_pubkey or "").strip()
    privkey = (cfg.identity_privkey or "").strip()

    if cfg.require_identity and (not pubkey or not privkey):
        raise HandshakeRejected("identity_required_but_missing_keys")

    if pubkey and privkey:
        try:
            from weall.net.peer_identity import sign_peer_hello_identity

            identity = sign_peer_hello_identity(
                header=hdr,
                peer_id=peer_id,
                pubkey=pubkey,
                privkey=privkey,
                agent=cfg.agent or _default_agent(),
                nonce=hello_nonce,
            )
        except Exception:
            # Fail-closed in production posture when identity is required.
            if cfg.require_identity:
                raise HandshakeRejected("identity_sign_failed")
            # Otherwise: fail-open (dev/test convenience).
            identity = None

    if cfg.require_identity and not (isinstance(identity, dict) and identity):
        raise HandshakeRejected("identity_required_but_missing_identity")

    return PeerHello(
        header=hdr,
        peer_id=peer_id,
        agent=cfg.agent or _default_agent(),
        nonce=hello_nonce,
        caps=tuple(cfg.caps or ()),
        identity=identity,
    )


def build_hello_ack(
    cfg: HandshakeConfig,
    *,
    corr_id: Optional[str],
    ok: bool,
    reason: Optional[str] = None,
    caps: Optional[Tuple[str, ...]] = None,
) -> PeerHelloAck:
    """Create an outbound HELLO_ACK message."""

    chain_id = _validate_non_empty(cfg.chain_id, "chain_id")
    schema_version = _validate_non_empty(cfg.schema_version, "schema_version")
    tx_index_hash = _validate_non_empty(cfg.tx_index_hash, "tx_index_hash")
    peer_id = _validate_non_empty(cfg.peer_id, "peer_id")

    hdr = WireHeader(
        type=MsgType.PEER_HELLO_ACK,
        chain_id=chain_id,
        schema_version=schema_version,
        tx_index_hash=tx_index_hash,
        sent_ts_ms=_now_ms(),
        corr_id=corr_id,
    )

    return PeerHelloAck(
        header=hdr,
        peer_id=peer_id,
        ok=bool(ok),
        reason=reason,
        caps=tuple(caps or ()),
        server_ts_ms=_now_ms(),
    )


# ---------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------


def process_inbound_hello(state: HandshakeState, msg: PeerHello) -> PeerHelloAck:
    """Handle an inbound HELLO and produce a HELLO_ACK to send back.

    Enforces strict compatibility.
    On success, establishes a session.

    NOTE: peer identity verification is performed at net/node.py because it
    requires a ledger snapshot.
    """

    cfg = state.config
    try:
        # Validate header invariants.
        if msg.header.chain_id != cfg.chain_id:
            raise HandshakeRejected("chain_id_mismatch")
        if msg.header.schema_version != cfg.schema_version:
            raise HandshakeRejected("schema_version_mismatch")
        if msg.header.tx_index_hash != cfg.tx_index_hash:
            raise HandshakeRejected("tx_index_hash_mismatch")

        # Validate peer_id.
        _validate_non_empty(msg.peer_id, "peer_id")

        # Establish session.
        state.status = "ESTABLISHED"
        state.session_id = _new_session_id()
        state.last_error = None

        return build_hello_ack(
            cfg,
            corr_id=getattr(msg.header, "corr_id", None),
            ok=True,
            reason=None,
            caps=tuple(cfg.caps or ()),
        )

    except HandshakeRejected as he:
        state.status = "REJECTED"
        state.session_id = None
        state.last_error = he.reason
        return build_hello_ack(
            cfg,
            corr_id=getattr(msg.header, "corr_id", None),
            ok=False,
            reason=he.reason,
            caps=tuple(cfg.caps or ()),
        )


def process_inbound_ack(state: HandshakeState, msg: PeerHelloAck) -> None:
    """Handle inbound HELLO_ACK after we sent HELLO."""

    if state.status not in {"SENT_HELLO"}:
        raise HandshakeError("unexpected_hello_ack")

    if not msg.ok:
        state.status = "REJECTED"
        state.session_id = None
        state.last_error = str(msg.reason or "handshake_rejected")
        raise HandshakeRejected(state.last_error)

    # Success.
    state.status = "ESTABLISHED"
    state.session_id = _new_session_id()
    state.last_error = None


def initiate(state: HandshakeState) -> PeerHello:
    """Start handshake: build HELLO and update state."""

    state.start()
    hello = build_hello(state.config)
    state.status = "SENT_HELLO"
    state.outbound_corr_id = getattr(hello.header, "corr_id", None)
    return hello


# ---------------------------------------------------------------------
# Compatibility helpers (router/tests expect these names)
# ---------------------------------------------------------------------


def begin_outbound_handshake(state: HandshakeState) -> PeerHello:
    """Legacy name used by router/tests: start and return outbound HELLO."""
    return initiate(state)


def require_established(state: HandshakeState) -> None:
    """Legacy helper used by router to enforce session establishment."""
    if not isinstance(state, HandshakeState):
        raise HandshakeRejected("invalid_handshake_state")
    if not state.is_established():
        raise HandshakeRejected("handshake_not_established")
