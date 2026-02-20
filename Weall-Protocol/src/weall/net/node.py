from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from weall.net.codec import AnyWireMsg, WireDecodeError, decode_message, encode_message
from weall.net.gossip import Gossip, GossipConfig
from weall.net.handshake import HandshakeConfig, HandshakeState
from weall.net.messages import MsgType, WireHeader, TxEnvelopeMsg
from weall.net.router import HandshakeRejected, Router, SessionRequired, UnknownMessageType
from weall.net.state_sync import StateSyncService
from weall.net.transport_memory import InMemoryTransport
from weall.net.transport_tls import TlsTransport

Json = Dict[str, Any]


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


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
    """
    Policy contract expected by tests.

    Decode failure semantics:
      - 1st decode fail -> evict, not banned (if max_strikes > 1)
      - 2nd decode fail -> banned when max_strikes=2
    """
    max_strikes: int = 5
    ban_cooldown_ms: int = 60_000

    strike_decode_fail: int = 1
    strike_unknown_type: int = 2
    strike_session_required: int = 2
    strike_handshake_rejected: int = 10
    strike_internal_error: int = 1

    # --- Production hardening knobs ---
    # Drop packets larger than this many bytes before attempting decode.
    max_packet_bytes: int = 256 * 1024

    # Per-peer rate limits (token bucket). Defaults are intentionally generous
    # so unit tests and small dev networks are unaffected.
    rate_msgs_per_sec: int = 200
    burst_msgs: int = 400

    rate_bytes_per_sec: int = 2_000_000
    burst_bytes: int = 4_000_000

    # Strike applied when peer exceeds the rate limit.
    strike_rate_limited: int = 1


NetPolicy = PeerPolicy


@dataclass
class _PeerRec:
    router: Router

    # token bucket (in tokens). Stored as floats to avoid rounding drift.
    last_rate_ms: int = 0
    msg_tokens: float = 0.0
    byte_tokens: float = 0.0


def _make_transport(cfg: NetConfig):
    if cfg.server_cert and cfg.server_key:
        try:
            return TlsTransport(
                server_cert=cfg.server_cert,
                server_key=cfg.server_key,
                chain_id=cfg.chain_id,
                schema_version=cfg.schema_version,
                tx_index_hash=cfg.tx_index_hash,
                peer_id=cfg.peer_id,
                agent=cfg.agent,
                caps=cfg.caps,
                identity_pubkey=cfg.identity_pubkey,
                identity_privkey=cfg.identity_privkey,
            )  # type: ignore[call-arg]
        except TypeError:
            return TlsTransport(server_cert=cfg.server_cert, server_key=cfg.server_key)  # type: ignore[call-arg]

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
        peer_policy: Optional[PeerPolicy] = None,
        policy: Optional[PeerPolicy] = None,
    ) -> None:
        self.cfg = cfg
        self.peer_policy = peer_policy or policy or PeerPolicy()

        self.transport = _make_transport(cfg)
        self.gossip = Gossip(cfg=GossipConfig(chain_id=cfg.chain_id))

        self.on_tx = on_tx
        self.on_bft_proposal = on_bft_proposal
        self.on_bft_vote = on_bft_vote
        self.on_bft_qc = on_bft_qc
        self.on_bft_timeout = on_bft_timeout

        self.sync_service = sync_service
        self.ledger_provider = ledger_provider

        # routing/handshake state
        self._peers: Dict[str, _PeerRec] = {}

        # security state
        self._banned_until: Dict[str, int] = {}
        self._strikes: Dict[str, int] = {}

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

    def _evict_peer(self, peer_id: str) -> None:
        # Drop routing state but keep strike counts.
        self._peers.pop(peer_id, None)

    def _ban_peer(self, peer_id: str) -> None:
        self._banned_until[peer_id] = _now_ms() + int(self.peer_policy.ban_cooldown_ms)
        self._evict_peer(peer_id)
        # optional: reset strikes after ban
        self._strikes.pop(peer_id, None)

    def _strike(self, peer_id: str, n: int) -> None:
        cur = int(self._strikes.get(peer_id, 0) or 0)
        cur += int(n)
        self._strikes[peer_id] = cur
        if cur >= int(self.peer_policy.max_strikes):
            self._ban_peer(peer_id)

    # -------------------------
    # Tick loop
    # -------------------------

    def tick(self) -> None:
        self.transport.tick()
        for pkt in self.transport.recv():
            self._on_packet(pkt.peer_id, pkt.payload)

    def _ensure_peer(self, peer_id: str) -> _PeerRec:
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
        hs = HandshakeState(config=hs_cfg)
        # Initialize token buckets full (burst) so first packets are allowed.
        rec = _PeerRec(
            router=Router(handshake=hs),
            last_rate_ms=_now_ms(),
            msg_tokens=float(self.peer_policy.burst_msgs),
            byte_tokens=float(self.peer_policy.burst_bytes),
        )
        self._peers[peer_id] = rec
        return rec

    def _rate_allow(self, peer_id: str, rec: _PeerRec, payload_len: int) -> bool:
        """Per-peer token bucket.

        Returns True if allowed, False if rate-limited.
        """
        now = _now_ms()
        last = int(rec.last_rate_ms or now)
        if now < last:
            last = now

        dt_ms = now - last
        rec.last_rate_ms = now

        # Refill buckets.
        if dt_ms > 0:
            dt_s = float(dt_ms) / 1000.0
            rec.msg_tokens = min(
                float(self.peer_policy.burst_msgs),
                float(rec.msg_tokens) + dt_s * float(self.peer_policy.rate_msgs_per_sec),
            )
            rec.byte_tokens = min(
                float(self.peer_policy.burst_bytes),
                float(rec.byte_tokens) + dt_s * float(self.peer_policy.rate_bytes_per_sec),
            )

        # Spend.
        if rec.msg_tokens < 1.0 or rec.byte_tokens < float(max(0, payload_len)):
            return False
        rec.msg_tokens -= 1.0
        rec.byte_tokens -= float(max(0, payload_len))
        return True

    def _on_packet(self, peer_id: str, payload: bytes) -> None:
        if not peer_id:
            return
        if self.is_banned(peer_id):
            return

        # Hard size cap before decode (DoS guard).
        if payload is None:
            payload = b""
        if len(payload) > int(self.peer_policy.max_packet_bytes):
            # Treat as decode failure for strike accounting, but do not attempt parse.
            self._strike(peer_id, self.peer_policy.strike_decode_fail)
            self._evict_peer(peer_id)
            return

        rec = self._ensure_peer(peer_id)

        # Rate limiting (DoS guard).
        if not self._rate_allow(peer_id, rec, len(payload)):
            self._strike(peer_id, self.peer_policy.strike_rate_limited)
            return

        # Decode
        try:
            msg = decode_message(payload)
        except WireDecodeError:
            self._strike(peer_id, self.peer_policy.strike_decode_fail)
            self._evict_peer(peer_id)
            return

        # Header sanity
        try:
            hdr: WireHeader = msg.header  # type: ignore[assignment]
        except Exception:
            self._strike(peer_id, self.peer_policy.strike_decode_fail)
            self._evict_peer(peer_id)
            return

        if str(hdr.chain_id) != str(self.cfg.chain_id) or str(hdr.schema_version) != str(self.cfg.schema_version):
            self._strike(peer_id, self.peer_policy.strike_unknown_type)
            return
        if str(hdr.tx_index_hash) != str(self.cfg.tx_index_hash):
            self._strike(peer_id, self.peer_policy.strike_unknown_type)
            return

        # Route
        try:
            self._route_message(peer_id, rec, msg)
        except SessionRequired:
            self._strike(peer_id, self.peer_policy.strike_session_required)
        except HandshakeRejected:
            self._strike(peer_id, self.peer_policy.strike_handshake_rejected)
        except UnknownMessageType:
            self._strike(peer_id, self.peer_policy.strike_unknown_type)
        except Exception:
            self._strike(peer_id, self.peer_policy.strike_internal_error)

    def _route_message(self, peer_id: str, rec: _PeerRec, msg: AnyWireMsg) -> None:
        rec.router.on_tx = (lambda m: self.on_tx(peer_id, m)) if self.on_tx is not None else None

        rec.router.on_bft_proposal = (lambda m: self.on_bft_proposal(peer_id, m)) if self.on_bft_proposal is not None else None
        rec.router.on_bft_vote = (lambda m: self.on_bft_vote(peer_id, m)) if self.on_bft_vote is not None else None
        rec.router.on_bft_qc = (lambda m: self.on_bft_qc(peer_id, m)) if self.on_bft_qc is not None else None
        rec.router.on_bft_timeout = (lambda m: self.on_bft_timeout(peer_id, m)) if self.on_bft_timeout is not None else None

        rec.router.on_sync_request = (lambda req: self.sync_service.handle_request(req)) if self.sync_service is not None else None

        resp = rec.router.handle_message(msg)
        if resp is not None:
            self.send_message(peer_id, resp)

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
                return

    def broadcast_message(self, msg: AnyWireMsg) -> None:
        payload = encode_message(msg)
        for c in self.transport.connections():
            pid = getattr(c, "peer_id", None)
            if not pid or self.is_banned(pid):
                continue
            try:
                c.send(payload)
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
