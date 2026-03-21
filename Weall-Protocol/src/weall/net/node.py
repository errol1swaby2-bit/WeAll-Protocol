# File: src/weall/net/node.py
from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from weall.net.codec import decode_message, encode_message
from weall.net.handshake import (
    HandshakeConfig,
    HandshakeRejected,
    HandshakeState,
    begin_outbound_handshake,
)
from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    PeerHello,
    PongMsg,
    StateSyncRequestMsg,
    StateSyncResponseMsg,
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
from weall.runtime.bft_hotstuff import validator_set_hash as _canonical_validator_set_hash
from weall.runtime.protocol_profile import (
    active_consensus_profile,
    runtime_protocol_profile_hash,
    runtime_protocol_version,
)

Json = dict[str, Any]


def _env_str(key: str, default: str = "") -> str:
    v = os.environ.get(key)
    return default if v is None else str(v)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _env_int(key: str, default: int = 0) -> int:
    v = os.environ.get(key)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip() or str(default))
    except Exception as exc:
        mode = str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"
        if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
            mode = "test"
        if mode == "prod":
            raise ValueError(f"invalid_integer_env:{key}") from exc
        return int(default)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _make_header(cfg: NetConfig, mtype: str) -> WireHeader:
    return WireHeader(
        type=mtype,
        chain_id=cfg.chain_id,
        schema_version=cfg.schema_version,
        tx_index_hash=cfg.tx_index_hash,
    )


def _normalize_validators(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        s = str(raw or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return tuple(out)


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
    caps: tuple[str, ...] = ()

    # Optional node identity material (hex strings)
    identity_pubkey: str | None = None
    identity_privkey: str | None = None

    # Optional TLS server material (paths or PEM strings). Used when WEALL_NET_TRANSPORT=tls.
    server_cert: str | None = None
    server_key: str | None = None


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

    # Exact duplicate payload suppression (per peer, bounded LRU window).
    duplicate_cache_entries: int = 256
    duplicate_cache_ttl_ms: int = 15_000

    # Bound peer bookkeeping so spoofed / one-shot peer IDs cannot grow memory without bound.
    max_peer_records: int = 1024

    # Bound outstanding state-sync correlation tracking and replay suppression window.
    max_outstanding_sync_requests: int = 64
    sync_request_ttl_ms: int = 5_000
    recent_completed_sync_responses: int = 256


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

    # Exact duplicate raw-payload suppression (node-local abuse hardening only).
    recent_payload_digests: OrderedDict[str, int] = field(default_factory=OrderedDict)
    duplicate_payloads_dropped: int = 0

    # Activity tracking for bounded peer-record eviction.
    last_seen_ms: int = 0
    established_at_ms: int = 0
    packets_received: int = 0

    # State-sync abuse diagnostics.
    sync_responses_dropped: int = 0
    sync_unsolicited_dropped: int = 0
    sync_replayed_dropped: int = 0


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
        return TlsTransport(
            server_cert=cert, server_key=key, ca_file=ca_file, server_name=server_name
        )

    mode = str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        mode = "test"
    if mode == "prod" and str(os.environ.get("WEALL_NET_TRANSPORT") or "").strip():
        raise RuntimeError("invalid_net_transport")
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
        peer_policy: PeerPolicy | None = None,
        on_tx: Callable[[str, WireMessage], None] | None = None,
        on_bft_proposal: Callable[[str, BftProposalMsg], None] | None = None,
        on_bft_vote: Callable[[str, BftVoteMsg], None] | None = None,
        on_bft_qc: Callable[[str, BftQcMsg], None] | None = None,
        on_bft_timeout: Callable[[str, BftTimeoutMsg], None] | None = None,
        ledger_provider: Callable[[], Json] | None = None,
        sync_service: StateSyncService | None = None,
        transport: Transport | None = None,
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

        self._conns: dict[str, Connection] = {}
        self._peers: dict[str, _PeerRec] = {}
        self._sync_response_cap: int = max(1, _env_int("WEALL_NET_SYNC_RESPONSE_CACHE", 256))
        self._sync_request_timeout_ms: int = max(
            50, _env_int("WEALL_NET_SYNC_REQUEST_TIMEOUT_MS", 1_500)
        )
        self._sync_outstanding_cap: int = max(
            1,
            _env_int(
                "WEALL_NET_SYNC_OUTSTANDING_MAX",
                int(self.peer_policy.max_outstanding_sync_requests),
            ),
        )
        self._sync_request_ttl_ms: int = max(
            50,
            _env_int(
                "WEALL_NET_SYNC_REQUEST_TTL_MS",
                int(self.peer_policy.sync_request_ttl_ms),
            ),
        )
        self._sync_completed_cap: int = max(
            1,
            _env_int(
                "WEALL_NET_SYNC_COMPLETED_CACHE",
                int(self.peer_policy.recent_completed_sync_responses),
            ),
        )
        self._sync_responses: OrderedDict[str, StateSyncResponseMsg] = OrderedDict()
        self._sync_requests: OrderedDict[str, tuple[str, int]] = OrderedDict()
        self._sync_completed: OrderedDict[tuple[str, str], int] = OrderedDict()

    # ----------------------------
    # Peer state + rate limiting
    # ----------------------------

    def is_banned(self, peer_id: str) -> bool:
        rec = self._peers.get(peer_id)
        if not rec:
            return False
        return rec.banned_until_ms > _now_ms()

    def _ban(self, rec: _PeerRec, *, cooldown_ms: int | None = None) -> None:
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

    def _prune_recent_payload_digests(self, rec: _PeerRec, now_ms: int) -> None:
        ttl_ms = max(0, int(self.peer_policy.duplicate_cache_ttl_ms))
        cap = max(0, int(self.peer_policy.duplicate_cache_entries))
        cache = rec.recent_payload_digests
        if ttl_ms <= 0 or cap <= 0:
            try:
                cache.clear()
            except Exception:
                pass
            return
        cutoff = int(now_ms) - ttl_ms
        try:
            while cache:
                _digest, last_seen_ms = next(iter(cache.items()))
                if int(last_seen_ms) > cutoff and len(cache) <= cap:
                    break
                cache.popitem(last=False)
        except Exception:
            try:
                cache.clear()
            except Exception:
                pass

    def _is_duplicate_payload(self, rec: _PeerRec, payload: bytes, *, now_ms: int) -> bool:
        ttl_ms = max(0, int(self.peer_policy.duplicate_cache_ttl_ms))
        cap = max(0, int(self.peer_policy.duplicate_cache_entries))
        if ttl_ms <= 0 or cap <= 0 or not payload:
            return False
        self._prune_recent_payload_digests(rec, now_ms)
        digest = hashlib.blake2s(bytes(payload), digest_size=16).hexdigest()
        cache = rec.recent_payload_digests
        last_seen_ms = cache.get(digest)
        if last_seen_ms is not None and (int(now_ms) - int(last_seen_ms)) <= ttl_ms:
            try:
                del cache[digest]
            except Exception:
                pass
            cache[digest] = int(now_ms)
            rec.duplicate_payloads_dropped += 1
            return True
        cache[digest] = int(now_ms)
        while len(cache) > cap:
            cache.popitem(last=False)
        return False

    def _peer_is_established(self, rec: _PeerRec) -> bool:
        try:
            hs = getattr(rec.router, "handshake", None)
            return bool(getattr(hs, "is_established", lambda: False)())
        except Exception:
            return False

    def _touch_peer(self, rec: _PeerRec, *, now_ms: int) -> None:
        ts = int(now_ms if int(now_ms) > 0 else _now_ms())
        rec.last_seen_ms = max(int(rec.last_seen_ms), ts)
        rec.packets_received += 1
        if self._peer_is_established(rec) and int(rec.established_at_ms) <= 0:
            rec.established_at_ms = ts

    def _peer_is_connected(self, peer_id: str) -> bool:
        pid = str(peer_id or "").strip()
        if not pid:
            return False
        if pid in self._conns:
            return True
        try:
            for cc in self.transport.connections():
                if str(getattr(cc, "peer_id", "") or "").strip() == pid:
                    self._conns[pid] = cc
                    return True
        except Exception:
            return False
        return False

    def _peer_eviction_sort_key(self, rec: _PeerRec) -> tuple[int, int, int, int, str]:
        established = 1 if self._peer_is_established(rec) else 0
        connected = 1 if self._peer_is_connected(rec.peer_id) else 0
        banned = 1 if self.is_banned(rec.peer_id) else 0
        return (
            established,
            connected,
            banned,
            int(rec.last_seen_ms or 0),
            str(rec.peer_id or ""),
        )

    def _prune_peer_records(self, *, allow_connected: bool = False) -> None:
        cap = max(0, int(self.peer_policy.max_peer_records))
        if cap <= 0:
            return
        while len(self._peers) >= cap:
            victims: list[_PeerRec] = []
            for rec in self._peers.values():
                established = self._peer_is_established(rec)
                connected = self._peer_is_connected(rec.peer_id)
                if established:
                    continue
                if connected and not allow_connected:
                    continue
                victims.append(rec)
            if not victims:
                break
            victim = min(victims, key=self._peer_eviction_sort_key)
            self._peers.pop(str(victim.peer_id), None)
            self._conns.pop(str(victim.peer_id), None)

    # ----------------------------
    # Identity / BFT gates
    # ----------------------------

    def _get_ledger(self) -> Json | None:
        if not self.ledger_provider:
            return None
        try:
            return self.ledger_provider()
        except Exception:
            return None

    def _identity_required(self) -> bool:
        if _env_bool("WEALL_NET_REQUIRE_IDENTITY", False):
            return True
        if self._bft_enabled() and self._identity_required_for_bft():
            return True
        return self._local_validator_posture()

    def _identity_required_for_bft(self) -> bool:
        return _env_bool("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", False)

    def _bft_enabled(self) -> bool:
        return _env_bool("WEALL_BFT_ENABLED", False)

    def _local_validator_posture(self) -> bool:
        validator_account = str(os.environ.get("WEALL_VALIDATOR_ACCOUNT", "") or "").strip()
        if validator_account:
            return True
        ledger = self._get_ledger()
        if isinstance(ledger, dict) and self._is_validator(
            ledger, str(self.cfg.peer_id or "").strip()
        ):
            return True
        return False

    def _is_validator(self, ledger: Json, account_id: str) -> bool:
        roles = ledger.get("roles")
        if not isinstance(roles, dict):
            return False
        validators = roles.get("validators")
        if not isinstance(validators, dict):
            return False
        active = validators.get("active_set")
        return isinstance(active, list) and account_id in active

    def _handshake_validator_epoch(self) -> int:
        ledger = self._get_ledger() or {}
        consensus = ledger.get("consensus") if isinstance(ledger, dict) else {}
        if isinstance(consensus, dict):
            epochs = consensus.get("epochs")
            if isinstance(epochs, dict):
                try:
                    cur = int(epochs.get("current") or 0)
                    if cur > 0:
                        return cur
                except Exception:
                    pass
            validator_set = consensus.get("validator_set")
            if isinstance(validator_set, dict):
                try:
                    cur2 = int(validator_set.get("epoch") or 0)
                    if cur2 > 0:
                        return cur2
                except Exception:
                    pass
        return 0

    def _handshake_validator_set_hash(self) -> str:
        ledger = self._get_ledger() or {}
        consensus = ledger.get("consensus") if isinstance(ledger, dict) else {}
        if isinstance(consensus, dict):
            validator_set = consensus.get("validator_set")
            if isinstance(validator_set, dict):
                have = str(validator_set.get("set_hash") or "").strip()
                if have:
                    return have
        roles = ledger.get("roles") if isinstance(ledger, dict) else {}
        validators = roles.get("validators") if isinstance(roles, dict) else {}
        active = validators.get("active_set") if isinstance(validators, dict) else []
        vals = _normalize_validators(active)
        if not vals:
            return ""
        return _canonical_validator_set_hash(vals)

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
        if not (
            self._bft_enabled() and self._identity_required() and self._identity_required_for_bft()
        ):
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
    # Sync response cache
    # ----------------------------

    # ----------------------------
    # Sync response cache
    # ----------------------------

    def _prune_completed_sync_responses(self, *, now_ms: int | None = None) -> None:
        now = int(now_ms if now_ms is not None else _now_ms())
        cutoff = now - int(self._sync_request_ttl_ms)
        try:
            while self._sync_completed:
                (_peer_id, _corr_id), seen_ms = next(iter(self._sync_completed.items()))
                if int(seen_ms) > cutoff and len(self._sync_completed) <= int(
                    self._sync_completed_cap
                ):
                    break
                self._sync_completed.popitem(last=False)
        except Exception:
            try:
                self._sync_completed.clear()
            except Exception:
                pass

    def _prune_sync_requests(self, *, now_ms: int | None = None) -> None:
        now = int(now_ms if now_ms is not None else _now_ms())
        try:
            while self._sync_requests:
                _corr_id, (_peer_id, deadline_ms) = next(iter(self._sync_requests.items()))
                if int(deadline_ms) > now and len(self._sync_requests) <= int(
                    self._sync_outstanding_cap
                ):
                    break
                self._sync_requests.popitem(last=False)
        except Exception:
            try:
                self._sync_requests.clear()
            except Exception:
                pass

    def _drop_sync_response(self, peer_id: str, *, replayed: bool = False) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        rec = self._peers.get(pid)
        if rec is None:
            return
        rec.sync_responses_dropped += 1
        if replayed:
            rec.sync_replayed_dropped += 1
        else:
            rec.sync_unsolicited_dropped += 1

    def _register_sync_request(self, peer_id: str, corr_id: str, *, deadline_ms: int) -> None:
        pid = str(peer_id or "").strip()
        cid = str(corr_id or "").strip()
        if not pid or not cid:
            raise ValueError("state sync request requires peer_id and corr_id")
        now = _now_ms()
        self._prune_sync_requests(now_ms=now)
        self._prune_completed_sync_responses(now_ms=now)
        if cid in self._sync_requests:
            del self._sync_requests[cid]
        while len(self._sync_requests) >= int(self._sync_outstanding_cap):
            self._sync_requests.popitem(last=False)
        self._sync_requests[cid] = (
            pid,
            max(int(deadline_ms), now + int(self._sync_request_ttl_ms)),
        )

    def _complete_sync_request(self, corr_id: str, *, peer_id: str = "") -> None:
        cid = str(corr_id or "").strip()
        pid = str(peer_id or "").strip()
        if not cid:
            return
        try:
            if not pid:
                entry = self._sync_requests.pop(cid, None)
                if entry is not None:
                    pid = str(entry[0] or "").strip()
            else:
                self._sync_requests.pop(cid, None)
        except Exception:
            pass
        if pid:
            self._sync_completed[(pid, cid)] = _now_ms()
            while len(self._sync_completed) > int(self._sync_completed_cap):
                self._sync_completed.popitem(last=False)
            self._prune_completed_sync_responses()

    def _cache_sync_response(self, peer_id: str, msg: StateSyncResponseMsg) -> None:
        pid = str(peer_id or "").strip()
        try:
            corr_id = str(getattr(getattr(msg, "header", None), "corr_id", "") or "").strip()
        except Exception:
            corr_id = ""
        if not pid or not corr_id:
            self._drop_sync_response(pid, replayed=False)
            return
        now = _now_ms()
        self._prune_sync_requests(now_ms=now)
        self._prune_completed_sync_responses(now_ms=now)
        if (pid, corr_id) in self._sync_completed:
            self._drop_sync_response(pid, replayed=True)
            return
        outstanding = self._sync_requests.get(corr_id)
        if outstanding is None:
            self._drop_sync_response(pid, replayed=False)
            return
        expect_peer_id, deadline_ms = outstanding
        if int(deadline_ms) <= now:
            self._sync_requests.pop(corr_id, None)
            self._drop_sync_response(pid, replayed=False)
            return
        if str(expect_peer_id or "").strip() != pid:
            self._drop_sync_response(pid, replayed=False)
            return
        try:
            if corr_id in self._sync_responses:
                del self._sync_responses[corr_id]
            self._sync_responses[corr_id] = msg
            while len(self._sync_responses) > int(self._sync_response_cap):
                self._sync_responses.popitem(last=False)
        except Exception:
            return

    def pop_sync_response(self, corr_id: str) -> StateSyncResponseMsg | None:
        cid = str(corr_id or "").strip()
        if not cid:
            return None
        try:
            msg = self._sync_responses.pop(cid, None)
        except Exception:
            return None
        if msg is None:
            return None
        peer_id = ""
        try:
            entry = self._sync_requests.get(cid)
            if entry is not None:
                peer_id = str(entry[0] or "").strip()
        except Exception:
            peer_id = ""
        self._complete_sync_request(cid, peer_id=peer_id)
        return msg

    # ----------------------------
    # Peer creation + router wiring
    # ----------------------------

    def _ensure_peer(self, peer_id: str) -> _PeerRec:
        rec = self._peers.get(peer_id)
        if rec:
            return rec

        self._prune_peer_records()

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
                require_identity=self._identity_required(),
                protocol_version=runtime_protocol_version(),
                protocol_profile_hash=runtime_protocol_profile_hash(),
                validator_epoch=self._handshake_validator_epoch(),
                validator_set_hash=self._handshake_validator_set_hash(),
                bft_enabled=self._bft_enabled(),
                require_protocol_profile_match=bool(
                    active_consensus_profile().handshake_requires_profile_match
                ),
                require_validator_epoch_match_for_bft=bool(
                    active_consensus_profile().handshake_requires_validator_epoch_match_for_bft
                ),
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

        def _on_sync_request(msg: WireMessage) -> WireMessage | None:
            if not self.sync_service:
                return None
            return self.sync_service.handle_request(msg)  # type: ignore[arg-type]

        def _on_sync_response(msg: StateSyncResponseMsg) -> None:
            self._cache_sync_response(peer_id, msg)

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
            on_sync_response=_on_sync_response,
            on_ping=_on_ping,
        )

        rec = _PeerRec(peer_id=peer_id, router=router)
        rec.last_seen_ms = _now_ms()
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
        self._touch_peer(rec, now_ms=now)

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

        # Exact duplicate raw-payload suppression is a node-local abuse hardening
        # measure only. Keep it scoped to established sessions so pre-session
        # protocol violations still accumulate strikes exactly as before.
        established = self._peer_is_established(rec)
        if established and int(rec.established_at_ms) <= 0:
            rec.established_at_ms = int(now)
        mtype = getattr(getattr(msg, "header", None), "type", None)
        if (
            established
            and mtype not in {MsgType.PEER_HELLO, MsgType.PEER_HELLO_ACK}
            and self._is_duplicate_payload(rec, payload, now_ms=now)
        ):
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
            if int(self.peer_policy.fast_ban_mismatch_ms) > 0 and (
                "mismatch" in s or "protocol" in s
            ):
                self._ban(rec, cooldown_ms=int(self.peer_policy.fast_ban_mismatch_ms))
            return
        except Exception as e:
            if e.__class__.__name__ == "SessionRequired":
                self._strike(rec, int(self.peer_policy.strike_session_required))
                return
            self._strike(rec, int(self.peer_policy.strike_decode_fail))
            return

        if self._peer_is_established(rec) and int(rec.established_at_ms) <= 0:
            rec.established_at_ms = int(now)

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
            hello = begin_outbound_handshake(rec.router.handshake)
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

    def request_state_sync(
        self,
        peer_id: str,
        req: StateSyncRequestMsg,
        *,
        timeout_ms: int | None = None,
        max_packets: int = 250,
        pump: Callable[[], None] | None = None,
        sleep_ms: int = 10,
    ) -> StateSyncResponseMsg | None:
        pid = str(peer_id or "").strip()
        if not pid or not isinstance(req, StateSyncRequestMsg):
            return None

        try:
            corr_id = str(getattr(req.header, "corr_id", "") or "").strip()
        except Exception:
            corr_id = ""
        if not corr_id:
            raise ValueError("state sync request requires header.corr_id")

        self.pop_sync_response(corr_id)
        deadline = _now_ms() + int(
            timeout_ms if timeout_ms is not None else self._sync_request_timeout_ms
        )
        self._register_sync_request(pid, corr_id, deadline_ms=deadline)
        self.send_message(pid, req)
        while _now_ms() <= deadline:
            if pump is not None:
                try:
                    pump()
                except Exception:
                    pass
            else:
                self.tick(max_packets=int(max_packets))

            resp = self.pop_sync_response(corr_id)
            if resp is not None:
                return resp

            if sleep_ms > 0:
                try:
                    time.sleep(float(sleep_ms) / 1000.0)
                except Exception:
                    pass
        self._complete_sync_request(corr_id, peer_id=pid)
        return None

    def peers_debug(self) -> Json:
        """Best-effort read-only peer diagnostics for operator tooling."""
        self._refresh_conns()
        peers: list[Json] = []
        established = 0
        identity_verified = 0
        banned = 0

        for peer_id, rec in sorted(self._peers.items(), key=lambda kv: str(kv[0])):
            router = rec.router
            hs = getattr(router, "handshake", None)
            is_established = bool(getattr(hs, "is_established", lambda: False)())
            hs_state = hs
            if is_established:
                established += 1
            if bool(rec.identity_ok):
                identity_verified += 1
            if self.is_banned(peer_id):
                banned += 1

            last_error = ""
            try:
                last_error = str(
                    getattr(hs_state, "last_error", "") or getattr(router, "last_error", "") or ""
                ).strip()
            except Exception:
                last_error = ""

            peers.append(
                {
                    "peer_id": str(peer_id),
                    "established": is_established,
                    "identity_verified": bool(rec.identity_ok),
                    "account_id": str(rec.identity_account or ""),
                    "pubkey": str(rec.identity_pubkey or ""),
                    "strikes": int(rec.strikes),
                    "banned": self.is_banned(peer_id),
                    "banned_until_ms": int(rec.banned_until_ms),
                    "last_error": last_error,
                    "msg_tokens": int(rec.msg_tokens),
                    "byte_tokens": int(rec.byte_tokens),
                    "connected": bool(peer_id in self._conns),
                    "duplicate_payloads_dropped": int(rec.duplicate_payloads_dropped),
                    "duplicate_payload_cache_size": int(len(rec.recent_payload_digests)),
                    "last_seen_ms": int(rec.last_seen_ms),
                    "established_at_ms": int(rec.established_at_ms),
                    "packets_received": int(rec.packets_received),
                    "sync_responses_dropped": int(rec.sync_responses_dropped),
                    "sync_unsolicited_dropped": int(rec.sync_unsolicited_dropped),
                    "sync_replayed_dropped": int(rec.sync_replayed_dropped),
                }
            )

        return {
            "ok": True,
            "enabled": True,
            "counts": {
                "peers_total": int(len(self._peers)),
                "peers_established": int(established),
                "peers_identity_verified": int(identity_verified),
                "peers_banned": int(banned),
                "peer_record_capacity": int(self.peer_policy.max_peer_records),
                "sync_requests_outstanding": int(len(self._sync_requests)),
                "sync_response_cache": int(len(self._sync_responses)),
                "sync_completed_cache": int(len(self._sync_completed)),
                "sync_outstanding_capacity": int(self._sync_outstanding_cap),
            },
            "peers": peers,
        }

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
