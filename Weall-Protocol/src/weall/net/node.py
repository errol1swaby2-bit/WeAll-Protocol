from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from weall.net.codec import AnyWireMsg, WireDecodeError, decode_message, encode_message
from weall.net.gossip import Gossip, GossipConfig
from weall.net.handshake import HandshakeConfig, HandshakeState
from weall.net.messages import MsgType, WireHeader, TxEnvelopeMsg
from weall.net.peer_identity import verify_peer_hello_identity
from weall.net.peer_store import PeerSecurityStore
from weall.net.router import HandshakeRejected, Router, SessionRequired, UnknownMessageType, initiate_handshake
from weall.net.state_sync import StateSyncService
from weall.net.transport import PeerAddr, Transport
from weall.net.transport_memory import InMemoryTransport
from weall.net.transport_tcp import TcpTransport
from weall.net.transport_tls import TlsTransport
from weall.runtime.metrics import inc_counter

Json = Dict[str, Any]


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return str(default if v is None else v).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if not raw:
        return bool(default)
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _mode() -> str:
    # In test runs, default to a non-production mode so security defaults
    # don't break unit tests unless explicitly enabled.
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return (_env_str("WEALL_MODE", "prod").lower() or "prod").strip()


@dataclass(frozen=True, slots=True)
class NetConfig:
    chain_id: str
    schema_version: str
    tx_index_hash: str
    peer_id: str

    agent: str = "weall-node"
    caps: tuple[str, ...] = ()

    identity_pubkey: Optional[str] = None
    identity_privkey: Optional[str] = None

    # TLS material (production path). Tests omit these.
    server_cert: Optional[str] = None
    server_key: Optional[str] = None


@dataclass
class PeerPolicy:
    """Security policy for peers."""

    # Strike/bans (hard policy)
    max_strikes: int = 5
    ban_cooldown_ms: int = 60_000

    strike_decode_fail: int = 1
    strike_unknown_type: int = 2
    strike_session_required: int = 2
    strike_handshake_rejected: int = 10
    strike_internal_error: int = 1

    # Drop packets larger than this many bytes before attempting decode.
    max_packet_bytes: int = 256 * 1024

    # Rate limits (token bucket). Defaults are generous.
    rate_msgs_per_sec: int = 200
    burst_msgs: int = 400

    rate_bytes_per_sec: int = 2_000_000
    burst_bytes: int = 4_000_000

    strike_rate_limited: int = 1

    # Idle / keepalive
    ping_interval_ms: int = 15_000
    idle_timeout_ms: int = 60_000

    # Peer scoring (soft policy)
    # Score decays toward 0 over time.
    score_decay_per_sec: float = 0.10
    score_good_msg: float = 0.05
    score_bad_strike: float = 0.25
    score_evict_threshold: float = -2.0
    score_ban_threshold: float = -6.0
    score_max: float = 5.0

    # Persistence write debounce (avoid writing on every packet)
    persist_min_interval_ms: int = 250


NetPolicy = PeerPolicy


@dataclass
class _PeerRec:
    router: Router

    # token bucket
    last_rate_ms: int = 0
    msg_tokens: float = 0.0
    byte_tokens: float = 0.0

    # identity (optional)
    identity_checked: bool = False
    identity_ok: bool = False
    identity_reason: str = ""
    identity_account: str = ""
    identity_pubkey: str = ""

    # handshake pacing
    outbound_hello_sent: bool = False

    # liveness
    last_seen_ms: int = 0
    last_sent_ms: int = 0
    last_ping_ms: int = 0

    # scoring
    score: float = 0.0
    last_score_ms: int = 0

    # persistence
    last_persist_ms: int = 0


class _TransportCompat:
    """Adapter to present the legacy NetNode transport surface."""

    def __init__(self, *, inner: Transport, scheme: str) -> None:
        self._t = inner
        self._scheme = scheme
        self._inbox: list[Any] = []

    @property
    def scheme(self) -> str:
        return self._scheme

    def bind(self, host: str, port: int) -> None:
        self._t.bind(PeerAddr(f"{self._scheme}://{host}:{int(port)}"))

    def connect(self, uri: str) -> Any:
        return self._t.connect(PeerAddr(uri))

    def stop(self) -> None:
        self._t.close()

    def tick(self) -> None:
        self._inbox.extend(list(self._t.poll(max_packets=250)))

    def recv(self) -> list[Any]:
        out = list(self._inbox)
        self._inbox.clear()
        return out

    def connections(self) -> list[Any]:
        return list(self._t.connections())


def _make_transport(cfg: NetConfig):
    """Select transport."""

    selected = (_env_str("WEALL_NET_TRANSPORT", "").lower() or "").strip()
    if not selected:
        if os.environ.get("PYTEST_CURRENT_TEST"):
            selected = "memory"
        elif _mode() == "prod":
            try:
                t: Transport = TlsTransport.from_env()  # type: ignore[assignment]
                return _TransportCompat(inner=t, scheme="tls")
            except Exception:
                allow_plain = _env_bool("WEALL_NET_ALLOW_PLAINTEXT", False)
                if not allow_plain:
                    raise RuntimeError(
                        "WEALL_NET_TRANSPORT not set and TLS is not configured. "
                        "Set WEALL_NET_TRANSPORT=tls and provide TLS env vars, or set "
                        "WEALL_NET_ALLOW_PLAINTEXT=1 to allow tcp in production."
                    )
                selected = "tcp"
        else:
            selected = "memory"

    if selected == "tls":
        try:
            t: Transport = TlsTransport.from_env()  # type: ignore[assignment]
            return _TransportCompat(inner=t, scheme="tls")
        except Exception:
            if cfg.server_cert and cfg.server_key:
                t2: Transport = TlsTransport(server_cert=cfg.server_cert, server_key=cfg.server_key)  # type: ignore[assignment]
                return _TransportCompat(inner=t2, scheme="tls")
            raise

    if selected == "tcp":
        t3: Transport = TcpTransport()  # type: ignore[assignment]
        return _TransportCompat(inner=t3, scheme="tcp")

    return InMemoryTransport()


class NetNode:
    def __init__(
        self,
        *,
        cfg: NetConfig,
        on_tx: Optional[Callable[[str, TxEnvelopeMsg], None]] = None,
        on_bft_proposal: Optional[Callable[[str, Any], None]] = None,
        on_bft_vote: Optional[Callable[[str, Any], None]] = None,
        on_bft_qc: Optional[Callable[[str, Any], None]] = None,
        on_bft_timeout: Optional[Callable[[str, Any], None]] = None,
        sync_service: Optional[StateSyncService] = None,
        ledger_provider: Optional[Callable[[], Json]] = None,
        peer_store: Optional[PeerSecurityStore] = None,
        peer_policy: Optional[PeerPolicy] = None,
        policy: Optional[PeerPolicy] = None,
    ) -> None:
        self.cfg = cfg
        self.peer_policy = peer_policy or policy or PeerPolicy()
        self.peer_store = peer_store

        self.transport = _make_transport(cfg)
        self.gossip = Gossip(cfg=GossipConfig(chain_id=cfg.chain_id))

        self.on_tx = on_tx
        self.on_bft_proposal = on_bft_proposal
        self.on_bft_vote = on_bft_vote
        self.on_bft_qc = on_bft_qc
        self.on_bft_timeout = on_bft_timeout

        self.sync_service = sync_service
        self.ledger_provider = ledger_provider

        self._peers: Dict[str, _PeerRec] = {}
        self._banned_until: Dict[str, int] = {}
        self._strikes: Dict[str, int] = {}

        self._logger = logging.getLogger("weall.net")

    # -------------------------
    # Back-compat test hook
    # -------------------------

    def _handle_packet(self, pkt: Any) -> None:
        peer_id = getattr(pkt, "peer_id", "") or ""
        payload = getattr(pkt, "payload", b"") or b""
        self._on_packet(str(peer_id), bytes(payload))

    # -------------------------
    # Transport lifecycle
    # -------------------------

    def bind(self, host: str, port: int) -> None:
        self.transport.bind(host, port)

    def connect(self, uri: str) -> bool:
        uri = str(uri or "").strip()
        if not uri:
            return False
        if not hasattr(self.transport, "connect"):
            return False

        for c in self.transport.connections():
            if getattr(c, "peer_id", None) == uri:
                return True

        try:
            self.transport.connect(uri)  # type: ignore[attr-defined]
            return True
        except Exception:
            return False

    def stop(self) -> None:
        self.transport.stop()

    # -------------------------
    # Peer state
    # -------------------------

    def peer_ids(self) -> list[str]:
        return [c.peer_id for c in self.transport.connections() if getattr(c, "peer_id", None)]

    def session_is_established(self, peer_id: str) -> bool:
        rec = self._peers.get(peer_id)
        if rec is None:
            return False
        return bool(rec.router.handshake.is_established())

    def is_banned(self, peer_id: str) -> bool:
        until = int(self._banned_until.get(peer_id, 0) or 0)
        return _now_ms() < until

    def _persist_peer_state(self, peer_id: str, rec: Optional[_PeerRec]) -> None:
        if self.peer_store is None:
            return
        pid = str(peer_id or "").strip()
        if not pid:
            return

        now = _now_ms()
        # debounce
        if rec is not None and (now - int(rec.last_persist_ms or 0)) < int(self.peer_policy.persist_min_interval_ms):
            return

        strikes = int(self._strikes.get(pid, 0) or 0)
        banned_until = int(self._banned_until.get(pid, 0) or 0)
        score = float(rec.score) if rec is not None else 0.0

        try:
            self.peer_store.set_peer(
                peer_id=pid,
                strikes=strikes,
                banned_until_ms=banned_until,
                score=score,
                meta={
                    "identity_checked": bool(rec.identity_checked) if rec is not None else False,
                    "identity_ok": bool(rec.identity_ok) if rec is not None else False,
                    "identity_reason": str(rec.identity_reason) if rec is not None else "",
                    "identity_account": str(rec.identity_account) if rec is not None else "",
                    "identity_pubkey": str(rec.identity_pubkey) if rec is not None else "",
                },
            )
            if rec is not None:
                rec.last_persist_ms = now
        except Exception:
            return

    def _load_peer_state(self, peer_id: str, rec: Optional[_PeerRec]) -> None:
        if self.peer_store is None:
            return
        pid = str(peer_id or "").strip()
        if not pid:
            return

        try:
            st = self.peer_store.get_peer(pid)
        except Exception:
            return

        if not isinstance(st, dict):
            return

        try:
            self._strikes[pid] = int(st.get("strikes") or 0)
        except Exception:
            pass

        try:
            self._banned_until[pid] = int(st.get("banned_until_ms") or 0)
        except Exception:
            pass

        try:
            if rec is not None:
                rec.score = float(st.get("score") or 0.0)
        except Exception:
            pass

        meta = st.get("meta")
        if isinstance(meta, dict) and rec is not None:
            try:
                rec.identity_checked = bool(meta.get("identity_checked", False))
                rec.identity_ok = bool(meta.get("identity_ok", False))
                rec.identity_reason = str(meta.get("identity_reason") or "")
                rec.identity_account = str(meta.get("identity_account") or "")
                rec.identity_pubkey = str(meta.get("identity_pubkey") or "")
            except Exception:
                pass

    def _ensure_peer(self, peer_id: str) -> _PeerRec:
        peer_id = str(peer_id or "").strip()
        rec = self._peers.get(peer_id)
        if rec is not None:
            return rec

        hs_cfg = HandshakeConfig(
            chain_id=self.cfg.chain_id,
            schema_version=self.cfg.schema_version,
            tx_index_hash=self.cfg.tx_index_hash,
            peer_id=self.cfg.peer_id,
            agent=self.cfg.agent,
            caps=self.cfg.caps,
            identity_pubkey=self.cfg.identity_pubkey,
            identity_privkey=self.cfg.identity_privkey,
        )
        router = Router(handshake=HandshakeState(config=hs_cfg))
        rec = _PeerRec(router=router)
        rec.last_rate_ms = _now_ms()
        rec.msg_tokens = float(self.peer_policy.burst_msgs)
        rec.byte_tokens = float(self.peer_policy.burst_bytes)
        rec.last_seen_ms = _now_ms()
        rec.last_sent_ms = _now_ms()
        rec.last_score_ms = _now_ms()

        self._peers[peer_id] = rec
        self._load_peer_state(peer_id, rec)
        return rec

    def _strike(self, peer_id: str, amount: int) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        cur = int(self._strikes.get(pid, 0) or 0)
        cur += int(amount)
        self._strikes[pid] = cur

        # score penalty
        rec = self._peers.get(pid)
        if rec is not None:
            self._score_update(pid, rec, delta=-float(self.peer_policy.score_bad_strike))

        # ban if exceed
        if cur >= int(self.peer_policy.max_strikes):
            self._ban(pid)

        self._persist_peer_state(pid, rec)

    def _ban(self, peer_id: str) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        until = _now_ms() + int(self.peer_policy.ban_cooldown_ms)
        self._banned_until[pid] = until
        rec = self._peers.get(pid)
        self._persist_peer_state(pid, rec)

    def _unban_expired(self) -> None:
        now = _now_ms()
        expired = [pid for pid, until in self._banned_until.items() if int(until) <= now]
        for pid in expired:
            self._banned_until.pop(pid, None)
            rec = self._peers.get(pid)
            self._persist_peer_state(pid, rec)

    def _rate_allow(self, peer_id: str, rec: _PeerRec, size: int) -> bool:
        now = _now_ms()
        dt = max(0, now - int(rec.last_rate_ms or 0))
        rec.last_rate_ms = now

        # replenish tokens
        rec.msg_tokens = min(
            float(self.peer_policy.burst_msgs),
            float(rec.msg_tokens) + (float(self.peer_policy.rate_msgs_per_sec) * (dt / 1000.0)),
        )
        rec.byte_tokens = min(
            float(self.peer_policy.burst_bytes),
            float(rec.byte_tokens) + (float(self.peer_policy.rate_bytes_per_sec) * (dt / 1000.0)),
        )

        # consume
        if rec.msg_tokens < 1.0:
            return False
        if rec.byte_tokens < float(size):
            return False

        rec.msg_tokens -= 1.0
        rec.byte_tokens -= float(size)
        return True

    def _score_update(self, peer_id: str, rec: _PeerRec, *, delta: float) -> None:
        now = _now_ms()
        dt = max(0, now - int(rec.last_score_ms or 0))
        rec.last_score_ms = now

        # decay toward 0
        decay = float(self.peer_policy.score_decay_per_sec) * (dt / 1000.0)
        if rec.score > 0:
            rec.score = max(0.0, rec.score - decay)
        elif rec.score < 0:
            rec.score = min(0.0, rec.score + decay)

        rec.score += float(delta)
        rec.score = min(float(self.peer_policy.score_max), rec.score)
        rec.score = max(-100.0, rec.score)

        # soft eviction -> ban
        if rec.score <= float(self.peer_policy.score_ban_threshold):
            self._ban(str(peer_id))
        elif rec.score <= float(self.peer_policy.score_evict_threshold):
            # evict by banning briefly; caller may reconnect later
            self._ban(str(peer_id))

        self._persist_peer_state(str(peer_id), rec)

    # -------------------------
    # Main tick loop
    # -------------------------

    def tick(self) -> None:
        self._unban_expired()

        # transport poll
        try:
            self.transport.tick()
        except Exception:
            return

        # process inbound packets
        pkts = []
        try:
            pkts = list(self.transport.recv())
        except Exception:
            pkts = []

        for pkt in pkts:
            try:
                peer_id = str(getattr(pkt, "peer_id", "") or "")
                payload = bytes(getattr(pkt, "payload", b"") or b"")
                self._on_packet(peer_id, payload)
            except Exception:
                continue

        # keepalive / idle
        self._keepalive_tick()

    def _keepalive_tick(self) -> None:
        now = _now_ms()

        for pid, rec in list(self._peers.items()):
            if self.is_banned(pid):
                continue

            # Initiate handshake for connected peers (lazy)
            if not rec.router.handshake.is_established():
                # Avoid spamming hello; send at most once per tick window.
                if not rec.outbound_hello_sent:
                    try:
                        hello = initiate_handshake(rec.router.handshake)
                        self.send_message(pid, hello)
                        rec.outbound_hello_sent = True
                        inc_counter("net_hello_sent_total", 1)
                    except Exception:
                        pass

            # idle timeout
            if rec.last_seen_ms and (now - int(rec.last_seen_ms)) > int(self.peer_policy.idle_timeout_ms):
                # soft ban
                self._ban(pid)
                inc_counter("net_idle_ban_total", 1)
                continue

            # ping interval
            if rec.router.handshake.is_established():
                if rec.last_ping_ms and (now - int(rec.last_ping_ms)) < int(self.peer_policy.ping_interval_ms):
                    continue
                try:
                    from weall.net.messages import PingMsg

                    ph = WireHeader(
                        type=MsgType.PING,
                        chain_id=self.cfg.chain_id,
                        schema_version=self.cfg.schema_version,
                        tx_index_hash=self.cfg.tx_index_hash,
                        sent_ts_ms=_now_ms(),
                        corr_id=None,
                    )
                    ping_id = str(_now_ms())
                    self.send_message(pid, PingMsg(header=ph, ping_id=ping_id))
                    rec.last_ping_ms = _now_ms()
                    inc_counter("net_ping_sent_total", 1)
                except Exception:
                    continue

    # -------------------------
    # Packet processing
    # -------------------------

    def _on_packet(self, peer_id: str, payload: bytes) -> None:
        peer_id = str(peer_id or "").strip()
        if not peer_id:
            return

        if self.is_banned(peer_id):
            return

        rec = self._ensure_peer(peer_id)
        rec.last_seen_ms = _now_ms()

        # size drop
        if len(payload) > int(self.peer_policy.max_packet_bytes):
            self._strike(peer_id, self.peer_policy.strike_decode_fail)
            inc_counter("net_packet_too_large_total", 1)
            return

        # rate limit
        if not self._rate_allow(peer_id, rec, len(payload)):
            self._strike(peer_id, self.peer_policy.strike_rate_limited)
            inc_counter("net_rate_limited_total", 1)
            return

        # decode
        try:
            msg = decode_message(payload)
        except WireDecodeError:
            self._strike(peer_id, self.peer_policy.strike_decode_fail)
            inc_counter("net_decode_fail_total", 1)
            return

        # header validation (strict)
        try:
            if msg.header.chain_id != self.cfg.chain_id:
                raise HandshakeRejected("chain_id_mismatch")
            if msg.header.schema_version != self.cfg.schema_version:
                raise HandshakeRejected("schema_version_mismatch")
            if msg.header.tx_index_hash != self.cfg.tx_index_hash:
                raise HandshakeRejected("tx_index_hash_mismatch")
        except HandshakeRejected:
            self._strike(peer_id, self.peer_policy.strike_handshake_rejected)
            inc_counter("net_handshake_rejected_total", 1)
            return

        # Identity verification on HELLO (optional / production gate)
        if getattr(msg.header, "type", None) == MsgType.PEER_HELLO:
            try:
                ledger = self.ledger_provider() if self.ledger_provider is not None else {}
                hello = msg
                ok, reason, account_id, pubkey = verify_peer_hello_identity(hello=hello, ledger=_as_dict(ledger))  # type: ignore[arg-type]
                rec.identity_checked = True
                rec.identity_ok = bool(ok)
                rec.identity_reason = str(reason)
                rec.identity_account = str(account_id)
                rec.identity_pubkey = str(pubkey)

                require_identity = _env_bool("WEALL_NET_REQUIRE_IDENTITY", True if _mode() == "prod" else False)
                identity_obj = getattr(hello, "identity", None)
                identity_present = isinstance(identity_obj, dict) and bool(identity_obj)

                if require_identity and not ok:
                    raise HandshakeRejected(str(reason))
                if identity_present and not ok:
                    raise HandshakeRejected(str(reason))
            except HandshakeRejected:
                raise
            except Exception:
                if _env_bool("WEALL_NET_REQUIRE_IDENTITY", True if _mode() == "prod" else False):
                    raise HandshakeRejected("identity_verify_exception")

        try:
            # Keepalive
            if getattr(msg.header, "type", None) == MsgType.PING:
                if not rec.router.handshake.is_established():
                    raise SessionRequired("session_required")
                try:
                    from weall.net.messages import PongMsg

                    ph = WireHeader(
                        type=MsgType.PONG,
                        chain_id=self.cfg.chain_id,
                        schema_version=self.cfg.schema_version,
                        tx_index_hash=self.cfg.tx_index_hash,
                        sent_ts_ms=_now_ms(),
                        corr_id=getattr(msg.header, "corr_id", None),
                    )
                    ping_id = getattr(msg, "ping_id", None)
                    self.send_message(peer_id, PongMsg(header=ph, ping_id=ping_id))
                    inc_counter("net_pong_sent_total", 1)
                except Exception:
                    pass
                return

            if getattr(msg.header, "type", None) == MsgType.PONG:
                return

            # BFT sender gating (production hardening): only active validators with verified identity
            # may send HotStuff messages.
            if getattr(msg.header, "type", None) in {MsgType.BFT_PROPOSAL, MsgType.BFT_VOTE, MsgType.BFT_QC, MsgType.BFT_TIMEOUT}:
                if _env_bool("WEALL_BFT_ENABLED", False):
                    self._enforce_bft_sender(peer_id, rec, msg)

            self._route_message(peer_id, rec, msg)
            self._score_update(peer_id, rec, delta=float(self.peer_policy.score_good_msg))
            inc_counter("net_msg_routed_total", 1)
        except SessionRequired:
            self._strike(peer_id, self.peer_policy.strike_session_required)
            inc_counter("net_session_required_total", 1)
        except HandshakeRejected:
            self._strike(peer_id, self.peer_policy.strike_handshake_rejected)
            inc_counter("net_handshake_rejected_total", 1)
        except UnknownMessageType:
            self._strike(peer_id, self.peer_policy.strike_unknown_type)
            inc_counter("net_unknown_type_total", 1)
        except Exception:
            self._strike(peer_id, self.peer_policy.strike_internal_error)
            inc_counter("net_internal_error_total", 1)

    def _route_message(self, peer_id: str, rec: _PeerRec, msg: AnyWireMsg) -> None:
        rec.router.on_tx = (lambda m: self.on_tx(peer_id, m)) if self.on_tx is not None else None

        rec.router.on_bft_proposal = (
            (lambda m: self.on_bft_proposal(peer_id, m)) if self.on_bft_proposal is not None else None
        )
        rec.router.on_bft_vote = (lambda m: self.on_bft_vote(peer_id, m)) if self.on_bft_vote is not None else None
        rec.router.on_bft_qc = (lambda m: self.on_bft_qc(peer_id, m)) if self.on_bft_qc is not None else None
        rec.router.on_bft_timeout = (
            (lambda m: self.on_bft_timeout(peer_id, m)) if self.on_bft_timeout is not None else None
        )

        rec.router.on_sync_request = (
            (lambda req: self.sync_service.handle_request(req)) if self.sync_service is not None else None
        )

        resp = rec.router.handle_message(msg)
        if resp is not None:
            self.send_message(peer_id, resp)

    # -------------------------
    # BFT sender gating
    # -------------------------

    def _active_validators_from_ledger(self, ledger: Json) -> set[str]:
        roles = ledger.get("roles")
        if not isinstance(roles, dict):
            return set()
        v = roles.get("validators")
        if not isinstance(v, dict):
            return set()
        aset = v.get("active_set")
        if not isinstance(aset, list):
            return set()
        out: set[str] = set()
        for x in aset:
            s = str(x).strip()
            if s:
                out.add(s)
        return out

    def _pinned_validators_env(self) -> set[str]:
        raw = _env_str("WEALL_NET_PINNED_VALIDATORS", "").strip()
        if not raw:
            return set()
        out: set[str] = set()
        for part in raw.replace(";", ",").split(","):
            s = str(part).strip()
            if s:
                out.add(s)
        return out

    def _enforce_bft_sender(self, peer_id: str, rec: _PeerRec, msg: AnyWireMsg) -> None:
        """Fail-closed checks for BFT messages.

        Threat model: without gating, any connected peer can spam/poison the BFT
        pipeline with bogus proposals/votes/timeouts/QCs.

        Policy:
          - If WEALL_BFT_ENABLED=1, BFT traffic MUST come from an identity-verified
            peer whose account is in the active validator set (or explicitly pinned).
          - For messages that carry a signer/proposer, it MUST match the verified
            identity account bound during the PEER_HELLO step.
        """

        require_identity = _env_bool(
            "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT",
            True if _mode() == "prod" else True,
        )

        if require_identity and (not rec.identity_checked or not rec.identity_ok):
            raise HandshakeRejected("bft_identity_required")

        acct = str(rec.identity_account or "").strip()
        if require_identity and not acct:
            raise HandshakeRejected("bft_missing_account")

        if self.ledger_provider is None or not callable(self.ledger_provider):
            if _mode() == "prod":
                raise HandshakeRejected("bft_ledger_required")
            return

        try:
            ledger = self.ledger_provider()
        except Exception:
            if _mode() == "prod":
                raise HandshakeRejected("bft_ledger_unavailable")
            return

        led = _as_dict(ledger)
        active = self._active_validators_from_ledger(led)
        pinned = self._pinned_validators_env()

        # If pinned validators are configured, they are the allowlist.
        if pinned:
            if acct not in pinned:
                raise HandshakeRejected("bft_sender_not_pinned")
        else:
            if acct not in active:
                raise HandshakeRejected("bft_sender_not_validator")

        mtype = getattr(getattr(msg, "header", None), "type", None)

        # Enforce proposer/signer matches the verified identity for the connection.
        if mtype == MsgType.BFT_PROPOSAL:
            proposer = str(getattr(msg, "proposer", "") or "").strip()
            if proposer and proposer != acct:
                raise HandshakeRejected("bft_proposer_mismatch")

        if mtype == MsgType.BFT_VOTE:
            vote = getattr(msg, "vote", None)
            if isinstance(vote, dict):
                signer = str(vote.get("signer") or "").strip()
                pubkey = str(vote.get("pubkey") or "").strip()
                if signer and signer != acct:
                    raise HandshakeRejected("bft_vote_signer_mismatch")
                if rec.identity_pubkey and pubkey and pubkey != str(rec.identity_pubkey):
                    raise HandshakeRejected("bft_vote_pubkey_mismatch")
            else:
                raise HandshakeRejected("bft_vote_bad_shape")

        if mtype == MsgType.BFT_TIMEOUT:
            tmo = getattr(msg, "timeout", None)
            if isinstance(tmo, dict):
                signer = str(tmo.get("signer") or "").strip()
                pubkey = str(tmo.get("pubkey") or "").strip()
                if signer and signer != acct:
                    raise HandshakeRejected("bft_timeout_signer_mismatch")
                if rec.identity_pubkey and pubkey and pubkey != str(rec.identity_pubkey):
                    raise HandshakeRejected("bft_timeout_pubkey_mismatch")
            else:
                raise HandshakeRejected("bft_timeout_bad_shape")

        # BFT_QC does not carry a single signer; we only require that the sender is a
        # verified validator account (checked above).
        return

    # -------------------------
    # Sending
    # -------------------------

    def send_message(self, peer_id: str, msg: AnyWireMsg) -> None:
        if self.is_banned(peer_id):
            return
        payload = encode_message(msg)
        for c in self.transport.connections():
            if getattr(c, "peer_id", None) == peer_id:
                c.send(payload)
                try:
                    rec = self._peers.get(peer_id)
                    if rec is not None:
                        rec.last_sent_ms = _now_ms()
                except Exception:
                    pass
                return

    def broadcast_message(self, msg: AnyWireMsg) -> None:
        payload = encode_message(msg)
        for c in self.transport.connections():
            pid = getattr(c, "peer_id", None)
            if not pid or self.is_banned(pid):
                continue
            try:
                c.send(payload)
                try:
                    rec = self._peers.get(str(pid))
                    if rec is not None:
                        rec.last_sent_ms = _now_ms()
                except Exception:
                    pass
            except Exception:
                continue

    def broadcast_tx(self, tx: Json) -> None:
        hdr = WireHeader(
            type=MsgType.TX_ENVELOPE,
            chain_id=self.cfg.chain_id,
            schema_version=self.cfg.schema_version,
            tx_index_hash=self.cfg.tx_index_hash,
        )
        msg = TxEnvelopeMsg(header=hdr, nonce=0, tx=tx)
        self.broadcast_message(msg)

    # -------------------------
    # Debug
    # -------------------------

    def peers_debug(self) -> Dict[str, object]:
        peers: list[Dict[str, object]] = []
        established = 0
        identity_verified = 0
        banned = 0

        now = _now_ms()
        conns = {getattr(c, "peer_id", ""): c for c in self.transport.connections()}
        ids = set([pid for pid in conns.keys() if pid]) | set(self._peers.keys())

        for pid in sorted(ids):
            if not pid:
                continue

            rec = self._peers.get(pid)
            hs_status = rec.router.handshake.status if rec is not None else "UNKNOWN"
            sess = rec.router.handshake.session_id if rec is not None else None
            is_est = bool(rec.router.handshake.is_established()) if rec is not None else False
            if is_est:
                established += 1

            is_id_ok = bool(rec.identity_ok) if rec is not None and rec.identity_checked else False
            if is_id_ok:
                identity_verified += 1

            until = int(self._banned_until.get(pid, 0) or 0)
            is_ban = now < until
            if is_ban:
                banned += 1

            peers.append(
                {
                    "peer_id": pid,
                    "connected": pid in conns,
                    "handshake": {
                        "status": hs_status,
                        "session_id": sess,
                        "outbound_hello_sent": bool(rec.outbound_hello_sent) if rec is not None else False,
                    },
                    "identity": {
                        "checked": bool(rec.identity_checked) if rec is not None else False,
                        "ok": bool(rec.identity_ok) if rec is not None else False,
                        "reason": str(rec.identity_reason) if rec is not None else "",
                        "account": str(rec.identity_account) if rec is not None else "",
                        "pubkey": str(rec.identity_pubkey) if rec is not None else "",
                    },
                    "security": {
                        "strikes": int(self._strikes.get(pid, 0) or 0),
                        "score": float(rec.score) if rec is not None else 0.0,
                        "banned": bool(is_ban),
                        "banned_until_ms": until if until else None,
                    },
                    "liveness": {
                        "last_seen_ms": int(rec.last_seen_ms) if rec is not None else None,
                        "last_sent_ms": int(rec.last_sent_ms) if rec is not None else None,
                        "last_ping_ms": int(rec.last_ping_ms) if rec is not None else None,
                    },
                }
            )

        return {
            "ok": True,
            "counts": {
                "peers_total": len(peers),
                "peers_established": established,
                "peers_identity_verified": identity_verified,
                "peers_banned": banned,
            },
            "peers": peers,
        }
