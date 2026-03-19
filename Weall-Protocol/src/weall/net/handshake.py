# File: src/weall/net/handshake.py
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from weall.net.messages import MsgType, PeerHello, PeerHelloAck, WireHeader
from weall.tx.canon import CanonError


class HandshakeError(RuntimeError):
    pass


class HandshakeRejected(HandshakeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


DEFAULT_HANDSHAKE_TIMEOUT_S = 10.0


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_corr_id() -> str:
    return secrets.token_hex(16)


def _new_session_id() -> str:
    return secrets.token_hex(24)


def _default_agent() -> str:
    return "weall-node"


def _validate_non_empty(s: Any, field: str) -> str:
    if not isinstance(s, str) or not s.strip():
        raise CanonError(f"{field} must be non-empty string")
    return s.strip()


def _normalize_opt_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _normalize_opt_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


@dataclass(frozen=True, slots=True)
class HandshakeConfig:
    chain_id: str
    schema_version: str
    tx_index_hash: str
    peer_id: str
    agent: str = "weall-node"
    caps: Tuple[str, ...] = ()
    identity_pubkey: Optional[str] = None
    identity_privkey: Optional[str] = None
    require_identity: bool = False
    protocol_version: str = ""
    protocol_profile_hash: str = ""
    validator_epoch: int = 0
    validator_set_hash: str = ""
    bft_enabled: bool = False
    require_protocol_profile_match: bool = False
    require_validator_epoch_match_for_bft: bool = False


@dataclass(slots=True)
class HandshakeState:
    config: HandshakeConfig
    status: str = "NEW"
    session_id: Optional[str] = None
    last_error: Optional[str] = None
    outbound_corr_id: Optional[str] = None
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


def build_hello(cfg: HandshakeConfig) -> PeerHello:
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
    hello_nonce = corr_id

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
            if cfg.require_identity:
                raise HandshakeRejected("identity_sign_failed")
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
        protocol_version=str(cfg.protocol_version or "").strip() or None,
        protocol_profile_hash=str(cfg.protocol_profile_hash or "").strip() or None,
        validator_epoch=int(cfg.validator_epoch) if int(cfg.validator_epoch) > 0 else None,
        validator_set_hash=str(cfg.validator_set_hash or "").strip() or None,
        bft_enabled=bool(cfg.bft_enabled),
    )


def build_hello_ack(
    cfg: HandshakeConfig,
    *,
    corr_id: Optional[str],
    ok: bool,
    reason: Optional[str] = None,
    caps: Optional[Tuple[str, ...]] = None,
) -> PeerHelloAck:
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
        protocol_version=str(cfg.protocol_version or "").strip() or None,
        protocol_profile_hash=str(cfg.protocol_profile_hash or "").strip() or None,
        validator_epoch=int(cfg.validator_epoch) if int(cfg.validator_epoch) > 0 else None,
        validator_set_hash=str(cfg.validator_set_hash or "").strip() or None,
        bft_enabled=bool(cfg.bft_enabled),
    )


def _check_protocol_profile(cfg: HandshakeConfig, *, protocol_version: Any, protocol_profile_hash: Any) -> None:
    if not cfg.require_protocol_profile_match:
        return
    local_version = _normalize_opt_str(cfg.protocol_version)
    remote_version = _normalize_opt_str(protocol_version)
    local_hash = _normalize_opt_str(cfg.protocol_profile_hash)
    remote_hash = _normalize_opt_str(protocol_profile_hash)
    if local_version and not remote_version:
        raise HandshakeRejected("protocol_version_missing")
    if local_hash and not remote_hash:
        raise HandshakeRejected("protocol_profile_hash_missing")
    if local_version and remote_version and local_version != remote_version:
        raise HandshakeRejected("protocol_version_mismatch")
    if local_hash and remote_hash and local_hash != remote_hash:
        raise HandshakeRejected("protocol_profile_hash_mismatch")


def _check_validator_metadata(
    cfg: HandshakeConfig,
    *,
    validator_epoch: Any,
    validator_set_hash: Any,
    bft_enabled: Any,
) -> None:
    if not cfg.require_validator_epoch_match_for_bft:
        return

    local_bft = bool(cfg.bft_enabled)
    remote_bft = bool(bft_enabled)
    local_epoch = int(cfg.validator_epoch)
    remote_epoch = _normalize_opt_int(validator_epoch)
    local_set_hash = _normalize_opt_str(cfg.validator_set_hash)
    remote_set_hash = _normalize_opt_str(validator_set_hash)

    # Mixed BFT posture is a consensus-affecting compatibility failure. Reject
    # when either side advertises validator metadata or enables BFT while the
    # other side does not.
    remote_has_validator_meta = remote_epoch > 0 or bool(remote_set_hash)
    local_has_validator_meta = local_epoch > 0 or bool(local_set_hash)
    if (local_bft != remote_bft) and (local_bft or remote_bft or local_has_validator_meta or remote_has_validator_meta):
        raise HandshakeRejected("bft_enabled_mismatch")

    if not local_bft and not remote_bft and not local_has_validator_meta and not remote_has_validator_meta:
        return

    # In strict BFT mode, both sides must explicitly advertise the validator
    # epoch and set-hash they believe are active. Allowing a restarted/rejoining
    # node to handshake without local validator metadata would silently admit a
    # peer before the operator has confirmed the node is on the expected epoch /
    # validator-set view.
    if local_bft or remote_bft:
        if local_epoch <= 0:
            raise HandshakeRejected("local_validator_epoch_missing")
        if remote_epoch <= 0:
            raise HandshakeRejected("validator_epoch_missing")
        if not local_set_hash:
            raise HandshakeRejected("local_validator_set_hash_missing")
        if not remote_set_hash:
            raise HandshakeRejected("validator_set_hash_missing")

    if local_epoch > 0 and remote_epoch > 0 and local_epoch != remote_epoch:
        raise HandshakeRejected("validator_epoch_mismatch")
    if local_set_hash and remote_set_hash and local_set_hash != remote_set_hash:
        raise HandshakeRejected("validator_set_hash_mismatch")


def process_inbound_hello(state: HandshakeState, msg: PeerHello) -> PeerHelloAck:
    cfg = state.config
    try:
        if msg.header.chain_id != cfg.chain_id:
            raise HandshakeRejected("chain_id_mismatch")
        if msg.header.schema_version != cfg.schema_version:
            raise HandshakeRejected("schema_version_mismatch")
        if msg.header.tx_index_hash != cfg.tx_index_hash:
            raise HandshakeRejected("tx_index_hash_mismatch")
        _validate_non_empty(msg.peer_id, "peer_id")
        _check_protocol_profile(
            cfg,
            protocol_version=getattr(msg, "protocol_version", None),
            protocol_profile_hash=getattr(msg, "protocol_profile_hash", None),
        )
        _check_validator_metadata(
            cfg,
            validator_epoch=getattr(msg, "validator_epoch", None),
            validator_set_hash=getattr(msg, "validator_set_hash", None),
            bft_enabled=getattr(msg, "bft_enabled", None),
        )
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
    if state.status not in {"SENT_HELLO"}:
        raise HandshakeError("unexpected_hello_ack")
    if not msg.ok:
        state.status = "REJECTED"
        state.session_id = None
        state.last_error = str(msg.reason or "handshake_rejected")
        raise HandshakeRejected(state.last_error)
    _check_protocol_profile(
        state.config,
        protocol_version=getattr(msg, "protocol_version", None),
        protocol_profile_hash=getattr(msg, "protocol_profile_hash", None),
    )
    _check_validator_metadata(
        state.config,
        validator_epoch=getattr(msg, "validator_epoch", None),
        validator_set_hash=getattr(msg, "validator_set_hash", None),
        bft_enabled=getattr(msg, "bft_enabled", None),
    )
    state.status = "ESTABLISHED"
    state.session_id = _new_session_id()
    state.last_error = None


def initiate(state: HandshakeState) -> PeerHello:
    state.start()
    hello = build_hello(state.config)
    state.status = "SENT_HELLO"
    state.outbound_corr_id = getattr(hello.header, "corr_id", None)
    return hello


def begin_outbound_handshake(state: HandshakeState) -> PeerHello:
    return initiate(state)


def require_established(state: HandshakeState) -> None:
    if not isinstance(state, HandshakeState):
        raise HandshakeRejected("invalid_handshake_state")
    if not state.is_established():
        raise HandshakeRejected("handshake_not_established")
