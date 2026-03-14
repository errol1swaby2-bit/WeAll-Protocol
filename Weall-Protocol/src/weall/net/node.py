# File: src/weall/net/node.py
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from weall.net.codec import decode_message, encode_message
from weall.net.handshake import HandshakeConfig, HandshakeRejected, HandshakeState, build_hello
from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    PeerHello,
    PeerHelloAck,
    PongMsg,
    WireHeader,
    WireMessage,
)
from weall.net.peer_identity import verify_peer_hello_identity
from weall.net.router import Router
from weall.net.state_sync import StateSyncService
from weall.net.transport import Connection, PeerAddr, Transport, WirePacket
from weall.net.transport_memory import InMemoryTransport
from weall.net.transport_tcp import TcpTransport
from weall.net.transport_tls import TlsTransport

Json = Dict[str, Any]


def _env_str(key: str, default: str = "") -> str:
    v = os.environ.get(key)
    return default if v is None else str(v)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _make_header(cfg: "NetConfig", mtype: str) -> WireHeader:
    return WireHeader(
        type=mtype,
        chain_id=cfg.chain_id,
        schema_version=cfg.schema_version,
        tx_index_hash=cfg.tx_index_hash,
    )


@dataclass(frozen=True, slots=True)
class NetConfig:
    """
    IMPORTANT: Keep constructor backwards compatible with tests.

    Tests create NetConfig(chain_id, schema_version, tx_index_hash, peer_id="me")
    so agent/caps must have defaults.
    """

    chain_id: str
    schema_version: str
    tx_index_hash: str

    peer_id: str = "local"
    agent: str = "weall-node"
    caps: Tuple[str, ...] = ()

    # Optional node identity material (hex strings)
    identity_pubkey: Optional[str] = None
    identity_privkey: Optional[str] = None

    # Optional TLS server material (paths or PEM strings). Used when WEALL_NET_TRANSPORT=tls.
    server_cert: Optional[str] = None
    server_key: Optional[str] = None


@dataclass(frozen=True, slots=True)
class PeerPolicy:
    """
    IMPORTANT: Keep keyword arguments compatible with tests.

    The tests expect:
      - max_packet_bytes
      - max_strikes, ban_cooldown_ms
      - strike_decode_fail, strike_rate_limited, strike_session_required, strike_handshake_rejected
      - rate_msgs_per_sec, burst_msgs, rate_bytes_per_sec, burst_bytes
      - fast_ban_mismatch_ms
    """

    max_strikes: int = 3
    ban_cooldown_ms: int = 60_000

    # Hardening limits
    max_packet_bytes: int = 256 * 1024

    # Token-bucket-ish rate limiter (per peer, best-effort)
    rate_msgs_per_sec: int = 50
    burst_msgs: int = 100
    rate_bytes_per_sec: int = 512 * 1024
    burst_bytes: int = 1 * 1024 * 1024

    # Strike weights
    strike_decode_fail: int = 1
    strike_rate_limited: int = 1
    strike_session_required: int = 1
    strike_handshake_rejected: int = 1

    # Protocol mismatch fast-ban window
    fast_ban_mismatch_ms: int = 0


@dataclass
class _PeerRec:
    peer_id: str
    router: Router
    strikes: int = 0
    banned_until_ms: int = 0

    # per-peer limiter state
    last_refill_ms: int = 0
    msg_tokens: float = 0.0
    byte_tokens: float = 0.0

    # Identity session info (set after PEER_HELLO acceptance)
    identity_ok: bool = False
    identity_account: str = ""
    identity_pubkey: str = ""


def _make_transport(cfg: NetConfig) -> Transport:
    kind = _env_str("WEALL_NET_TRANSPORT", "memory").lower().strip()
    if kind in {"mem", "memory", "inmem"}:
        return InMemoryTransport()
    if kind in {"tcp", "plain"}:
        return TcpTransport()
    if kind in {"tls", "ssl"}:
        cert = cfg.server_cert or _env_str("WEALL_NET_TLS_CERT", "").strip()
        key = cfg.server_key or _env_str("WEALL_NET_TLS_KEY", "").strip()
        ca_file = _env_str("WEALL_NET_TLS_CA", "").strip()
        server_name = _env_str("WEALL_NET_TLS_SERVER_NAME", "").strip()
        if not cert or not key:
            raise RuntimeError(
                "TLS transport selected but server cert/key not configured "
                "(cfg.server_cert/server_key or WEALL_NET_TLS_CERT/WEALL_NET_TLS_KEY)."
            )
        return TlsTransport(server_cert=cert, server_key=key, ca_file=ca_file, server_name=server_name)

    return InMemoryTransport()


class NetNode:
    """
    Networking edge for the protocol.

    Defensive by default:
      - Fail-closed on decode/protocol mismatches
      - Strike-based bans
      - Optional identity enforcement at handshake and for BFT
      - Optional inbound message routing for TX + HotStuff messages
    """

    def __init__(
        self,
        *,
        cfg: NetConfig,
        peer_policy: Optional[PeerPolicy] = None,
        on_tx: Optional[Callable[[str, WireMessage], None]] = None,
        on_bft_proposal: Optional[Callable[[str, BftProposalMsg], None]] = None,
        on_bft_vote: Optional[Callable[[str, BftVoteMsg], None]] = None,
        on_bft_qc: Optional[Callable[[str, BftQcMsg], None]] = None,
        on_bft_timeout: Optional[Callable[[str, BftTimeoutMsg], None]] = None,
        ledger_provider: Optional[Callable[[], Json]] = None,
        sync_service: Optional[StateSyncService] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        self.cfg = cfg
        self.peer_policy = peer_policy or PeerPolicy()

        self.on_tx = on_tx
        self.on_bft_proposal = on_bft_proposal
        self.on_bft_vote = on_bft_vote
        self.on_bft_qc = on_bft_qc
        self.on_bft_timeout = on_bft_timeout
        self.ledger_provider = ledger_provider
        self.sync_service = sync_service

        self.transport: Transport = transport or _make_transport(cfg)

        self._conns: Dict[str, Connection] = {}
        self._peers: Dict[str, _PeerRec] = {}

    # ----------------------------
    # Peer state + rate limiting
    # ----------------------------

    def is_banned(self, peer_id: str) -> bool:
        rec = self._peers.get(peer_id)
        if not rec:
            return False
        return rec.banned_until_ms > _now_ms()

    def _ban(self, rec: _PeerRec, *, cooldown_ms: Optional[int] = None) -> None:
        cd = int(cooldown_ms if cooldown_ms is not None else self.peer_policy.ban_cooldown_ms)
        rec.banned_until_ms = max(rec.banned_until_ms, _now_ms() + cd)

    def _strike(self, rec: _PeerRec, weight: int) -> None:
        if weight <= 0:
            return
        rec.strikes += int(weight)
        if rec.strikes >= int(self.peer_policy.max_strikes):
            self._ban(rec)

    def _refill_limits(self, rec: _PeerRec, now_ms: int) -> None:
        if rec.last_refill_ms == 0:
            rec.last_refill_ms = now_ms
            rec.msg_tokens = float(self.peer_policy.burst_msgs)
            rec.byte_tokens = float(self.peer_policy.burst_bytes)
            return

        dt = max(0, now_ms - rec.last_refill_ms)
        rec.last_refill_ms = now_ms

        rec.msg_tokens = min(
            float(self.peer_policy.burst_msgs),
            rec.msg_tokens + (dt / 1000.0) * float(self.peer_policy.rate_msgs_per_sec),
        )
        rec.byte_tokens = min(
            float(self.peer_policy.burst_bytes),
            rec.byte_tokens + (dt / 1000.0) * float(self.peer_policy.rate_bytes_per_sec),
        )

    def _rate_limit(self, rec: _PeerRec, payload_len: int, now_ms: int) -> bool:
        self._refill_limits(rec, now_ms)
        if rec.msg_tokens < 1.0 or rec.byte_tokens < float(payload_len):
            return False
        rec.msg_tokens -= 1.0
        rec.byte_tokens -= float(payload_len)
        return True

    # ----------------------------
    # Identity / BFT gates
    # ----------------------------

    def _get_ledger(self) -> Optional[Json]:
        if not self.ledger_provider:
            return None
        try:
            return self.ledger_provider()
        except Exception:
            return None

    def _identity_required(self) -> bool:
        return _env_bool("WEALL_NET_REQUIRE_IDENTITY", False)

    def _identity_required_for_bft(self) -> bool:
        return _env_bool("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", False)

    def _bft_enabled(self) -> bool:
        return _env_bool("WEALL_BFT_ENABLED", False)

    def _is_validator(self, ledger: Json, account_id: str) -> bool:
        roles = ledger.get("roles")
        if not isinstance(roles, dict):
            return False
        validators = roles.get("validators")
        if not isinstance(validators, dict):
            return False
        active = validators.get("active_set")
        return isinstance(active, list) and account_id in active

    def _verify_inbound_hello_identity(self, rec: _PeerRec, hello: PeerHello) -> None:
        if not self._identity_required():
            return

        ledger = self._get_ledger()
        if ledger is None:
            # Tests expect this path to strike/ban as a handshake rejection
            raise HandshakeRejected("identity_required_but_no_ledger")

        ok, reason, account_id, pubkey = verify_peer_hello_identity(hello=hello, ledger=ledger)
        if not ok:
            raise HandshakeRejected(f"identity_invalid:{reason}")

        rec.identity_ok = True
        rec.identity_account = account_id
        rec.identity_pubkey = pubkey

    def _enforce_bft_identity_gate(self, rec: _PeerRec, msg: BftVoteMsg) -> None:
        if not (self._bft_enabled() and self._identity_required() and self._identity_required_for_bft()):
            return

        if not rec.identity_ok:
            raise HandshakeRejected("bft_requires_identity")

        ledger = self._get_ledger()
        if ledger is None:
            raise HandshakeRejected("bft_requires_ledger")

        if not self._is_validator(ledger, rec.identity_account):
            raise HandshakeRejected("bft_requires_validator")

        vote = getattr(msg, "vote", None)
        if not isinstance(vote, dict):
            raise HandshakeRejected("bft_vote_invalid")

        signer = str(vote.get("signer", "")).strip()
        pubkey = str(vote.get("pubkey", "")).strip()
        if signer != rec.identity_account or pubkey != rec.identity_pubkey:
            raise HandshakeRejected("bft_identity_mismatch")

    # ----------------------------
    # Peer creation + router wiring
    # ----------------------------

    def _ensure_peer(self, peer_id: str) -> _PeerRec:
        rec = self._peers.get(peer_id)
        if rec:
            return rec

        hs = HandshakeState(
            config=HandshakeConfig(
                chain_id=self.cfg.chain_id,
                schema_version=self.cfg.schema_version,
                tx_index_hash=self.cfg.tx_index_hash,
                peer_id=self.cfg.peer_id,
                agent=self.cfg.agent,
                caps=self.cfg.caps,
                identity_pubkey=self.cfg.identity_pubkey,
                identity_privkey=self.cfg.identity_privkey,
                require_identity=_env_bool("WEALL_NET_REQUIRE_IDENTITY", False),
            )
        )

        def _on_tx(msg: WireMessage) -> None:
            if self.on_tx:
                self.on_tx(peer_id, msg)

        def _on_bft_vote(msg: BftVoteMsg) -> None:
            if self.on_bft_vote:
                self.on_bft_vote(peer_id, msg)

        def _on_bft_proposal(msg: BftProposalMsg) -> None:
            if self.on_bft_proposal:
                self.on_bft_proposal(peer_id, msg)

        def _on_bft_qc(msg: BftQcMsg) -> None:
            if self.on_bft_qc:
                self.on_bft_qc(peer_id, msg)

        def _on_bft_timeout(msg: BftTimeoutMsg) -> None:
            if self.on_bft_timeout:
                self.on_bft_timeout(peer_id, msg)

        def _on_sync_request(msg: WireMessage) -> Optional[WireMessage]:
            if not self.sync_service:
                return None
            return self.sync_service.handle_request(msg)  # type: ignore[arg-type]

        def _on_ping(msg: WireMessage) -> WireMessage:
            ping_id = getattr(msg, "ping_id", None)
            return PongMsg(header=_make_header(self.cfg, MsgType.PONG), ping_id=ping_id)

        router = Router(
            handshake=hs,
            on_tx=_on_tx,
            on_bft_vote=_on_bft_vote,
            on_bft_proposal=_on_bft_proposal,
            on_bft_qc=_on_bft_qc,
            on_bft_timeout=_on_bft_timeout,
            on_sync_request=_on_sync_request,
            on_ping=_on_ping,
        )

        rec = _PeerRec(peer_id=peer_id, router=router)
        self._peers[peer_id] = rec
        return rec

    # ----------------------------
    # Packet ingest
    # ----------------------------

    def _handle_packet(self, pkt: WirePacket) -> None:
        peer_id = str(getattr(pkt, "peer_id", "")).strip()
        payload = bytes(getattr(pkt, "payload", b"") or b"")
        now = int(getattr(pkt, "received_at_ms", 0) or 0)

        if now <= 0:
            now = _now_ms()

        if not peer_id:
            return

        rec = self._ensure_peer(peer_id)

        # If currently banned, ignore.
        if rec.banned_until_ms > _now_ms():
            return

        # Oversize guard (tests expect oversize counts as decode strike)
        if len(payload) > int(self.peer_policy.max_packet_bytes):
            self._strike(rec, int(self.peer_policy.strike_decode_fail))
            return

        # Rate limit (tests exercise this)
        if not self._rate_limit(rec, len(payload), now_ms=now):
            self._strike(rec, int(self.peer_policy.strike_rate_limited))
            return

        # Decode
        try:
            msg = decode_message(payload)
        except Exception:
            self._strike(rec, int(self.peer_policy.strike_decode_fail))
            return

        # Protocol mismatch checks (tests cover fast-ban)
        try:
            h = getattr(msg, "header", None)
            if h is None:
                self._strike(rec, int(self.peer_policy.strike_decode_fail))
                return

            if str(h.chain_id) != str(self.cfg.chain_id):
                self._strike(rec, int(self.peer_policy.strike_handshake_rejected))
                if int(self.peer_policy.fast_ban_mismatch_ms) > 0:
                    self._ban(rec, cooldown_ms=int(self.peer_policy.fast_ban_mismatch_ms))
                return

            if str(h.schema_version) != str(self.cfg.schema_version):
                self._strike(rec, int(self.peer_policy.strike_handshake_rejected))
                if int(self.peer_policy.fast_ban_mismatch_ms) > 0:
                    self._ban(rec, cooldown_ms=int(self.peer_policy.fast_ban_mismatch_ms))
                return

            if str(h.tx_index_hash) != str(self.cfg.tx_index_hash):
                self._strike(rec, int(self.peer_policy.strike_handshake_rejected))
                if int(self.peer_policy.fast_ban_mismatch_ms) > 0:
                    self._ban(rec, cooldown_ms=int(self.peer_policy.fast_ban_mismatch_ms))
                return
        except Exception:
            self._strike(rec, int(self.peer_policy.strike_decode_fail))
            return

        # Identity checks on inbound hello
        if getattr(msg.header, "type", None) == MsgType.PEER_HELLO:
            try:
                self._verify_inbound_hello_identity(rec, msg)  # type: ignore[arg-type]
            except HandshakeRejected:
                self._strike(rec, int(self.peer_policy.strike_handshake_rejected))
                if int(self.peer_policy.fast_ban_mismatch_ms) > 0:
                    self._ban(rec, cooldown_ms=int(self.peer_policy.fast_ban_mismatch_ms))
                return

        # BFT identity gate for votes
        if getattr(msg.header, "type", None) == MsgType.BFT_VOTE:
            try:
                self._enforce_bft_identity_gate(rec, msg)  # type: ignore[arg-type]
            except HandshakeRejected:
                self._strike(rec, int(self.peer_policy.strike_handshake_rejected))
                if int(self.peer_policy.max_strikes) <= 1:
                    self._ban(rec)
                return

        # Route (handshake/session enforcement is inside Router)
        try:
            resp = rec.router.handle_message(msg)
        except HandshakeRejected as e:
            # SessionRequired is expected and tested indirectly through strikes
            self._strike(rec, int(self.peer_policy.strike_handshake_rejected))
            s = str(getattr(e, "reason", e))
            if int(self.peer_policy.fast_ban_mismatch_ms) > 0 and ("mismatch" in s or "protocol" in s):
                self._ban(rec, cooldown_ms=int(self.peer_policy.fast_ban_mismatch_ms))
            return
        except Exception as e:
            if e.__class__.__name__ == "SessionRequired":
                self._strike(rec, int(self.peer_policy.strike_session_required))
                return
            self._strike(rec, int(self.peer_policy.strike_decode_fail))
            return

        # Send response if any
        if resp is not None:
            try:
                self.send_message(peer_id, resp)
            except Exception:
                pass

    # ----------------------------
    # Transport helpers (bind/connect/tick)
    # ----------------------------

    def bind(self, addr: PeerAddr) -> None:
        self.transport.bind(addr)

    def connect(self, addr: PeerAddr) -> Connection:
        conn = self.transport.connect(addr)
        self._conns[str(conn.peer_id)] = conn
        # Start handshake: send hello
        try:
            rec = self._ensure_peer(str(conn.peer_id))
            hello = build_hello(rec.router.handshake.config, corr_id=None)
            conn.send(encode_message(hello))
        except Exception:
            pass
        return conn

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception:
            pass
        self._conns.clear()
        self._peers.clear()

    def _refresh_conns(self) -> None:
        try:
            for c in self.transport.connections():
                try:
                    self._conns[str(c.peer_id)] = c
                except Exception:
                    continue
        except Exception:
            return

    def tick(self, *, max_packets: int = 250) -> None:
        self._refresh_conns()
        try:
            for pkt in self.transport.poll(max_packets=int(max_packets)):
                try:
                    self._handle_packet(pkt)
                except Exception:
                    continue
        except Exception:
            return

    # ----------------------------
    # Send helpers
    # ----------------------------

    def send_bytes(self, peer_id: str, payload: bytes) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        self._refresh_conns()
        c = self._conns.get(pid)
        if c is None:
            try:
                for cc in self.transport.connections():
                    if str(cc.peer_id) == pid:
                        c = cc
                        self._conns[pid] = cc
                        break
            except Exception:
                c = None
        if c is None:
            return
        c.send(bytes(payload))

    def send_message(self, peer_id: str, msg: WireMessage) -> None:
        self.send_bytes(peer_id, encode_message(msg))

    def broadcast_message(self, msg: WireMessage, *, exclude_peer_id: str = "") -> None:
        ex = str(exclude_peer_id or "").strip()
        payload = encode_message(msg)
        self._refresh_conns()
        for pid, c in list(self._conns.items()):
            if ex and pid == ex:
                continue
            try:
                c.send(payload)
            except Exception:
                continue

    def report_peer_fault(self, peer_id: str, *, strikes: int = 1, reason: str = "") -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        rec = self._peers.get(pid)
        if rec is None:
            rec = self._ensure_peer(pid)
        try:
            self._strike(rec, int(strikes) if int(strikes) > 0 else 1)
        except Exception:
            return
