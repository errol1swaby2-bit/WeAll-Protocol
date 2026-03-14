# File: src/weall/net/net_loop.py
from __future__ import annotations

"""
WeAll Protocol — Network Mesh Loop

This module runs the peer networking loop when WEALL_NET_ENABLED=1.

Goals (production posture):
  - Keep networking optional and fail-closed when misconfigured.
  - Use the canonical Transport/Connection interface (weall.net.transport).
  - Ensure peer-ingressed tx envelopes face the SAME admission + signature policy
    as HTTP (prod defaults to sig verification).

Important:
  - The net layer is not exercised by the unit test suite in most builds.
    This loop is therefore defensive and best-effort: it should never crash
    the node process if a peer misbehaves.

BFT note:
  - The runtime executor implements HotStuff-style handlers under bft_* names
    (bft_on_proposal/bft_on_vote/bft_on_qc/bft_on_timeout/bft_drive_timeouts/
     bft_leader_propose). The net layer bridges wire messages to those handlers
    and broadcasts any produced follow-up messages (votes, QCs, timeouts).
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from weall.ledger.state import LedgerView
from weall.net.messages import (
    BftProposalMsg,
    BftQcMsg,
    BftTimeoutMsg,
    BftVoteMsg,
    MsgType,
    TxEnvelopeMsg,
    WireHeader,
    WireMessage,
)
from weall.net.net_logging import log_event
from weall.net.node import NetConfig, NetNode
from weall.net.peer_list_store import PeerListStore
from weall.net.state_sync import StateSyncService
from weall.net.transport import PeerAddr
from weall.runtime.metrics import inc_counter
from weall.runtime.mempool import compute_tx_id
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_admission import admit_tx

Json = Dict[str, Any]

_LOG = logging.getLogger("weall.net.loop")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    s = str(v).strip().lower()
    if not s:
        return bool(default)
    return s in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        v = os.environ.get(name)
        if v is None:
            return int(default)
        s = str(v).strip()
        return int(s) if s else int(default)
    except Exception:
        return int(default)


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _peer_requires_sigverify() -> bool:
    """Mirror HTTP boundary policy for peer-ingress."""

    mode = _mode()
    override = os.environ.get("WEALL_SIGVERIFY")
    if override is None:
        return bool(mode == "prod")
    return str(override).strip() == "1"


def _split_csv(raw: str) -> list[str]:
    return [p.strip() for p in (raw or "").split(",") if p.strip()]


def _is_peer_uri(uri: str) -> bool:
    s = str(uri or "").strip()
    return s.startswith("tcp://") or s.startswith("tls://")


def _seed_net_self_url(seed: str) -> str:
    s = str(seed or "").strip()
    if not s:
        return ""
    # Allow passing a full /v1/net/self URL or a base URL.
    if "/v1/net/self" in s:
        return s
    s = s.rstrip("/")
    return f"{s}/v1/net/self"


def _http_get_json(url: str, *, timeout_s: float = 2.0) -> Optional[Json]:
    if not url:
        return None
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            data = resp.read()
        obj = json.loads(data.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None
    except Exception:
        return None


@dataclass
class NetLoopConfig:
    enabled: bool
    bind_host: str
    bind_port: int
    tick_ms: int
    schema_version: str


def net_loop_config_from_env() -> NetLoopConfig:
    enabled = _env_bool("WEALL_NET_ENABLED", False)
    bind_host = os.environ.get("WEALL_NET_BIND_HOST", "0.0.0.0")
    bind_port = _env_int("WEALL_NET_BIND_PORT", 30303)
    tick_ms = max(10, _env_int("WEALL_NET_TICK_MS", 25))
    schema_version = (os.environ.get("WEALL_NET_SCHEMA_VERSION") or "1").strip() or "1"
    return NetLoopConfig(
        enabled=bool(enabled),
        bind_host=str(bind_host),
        bind_port=int(bind_port),
        tick_ms=int(tick_ms),
        schema_version=str(schema_version),
    )


class NetMeshLoop:
    """Background networking loop for peer mesh + tx gossip + optional BFT messages."""

    def __init__(self, *, executor, mempool, cfg: Optional[NetLoopConfig] = None) -> None:
        self._executor = executor
        self._mempool = mempool
        self._cfg = cfg or net_loop_config_from_env()

        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None
        self._started = False

        peers_file = os.environ.get("WEALL_PEERS_FILE", "./data/peers.json")
        self._peers_store = PeerListStore(path=str(peers_file or "./data/peers.json"))

        env_peers_raw = (os.environ.get("WEALL_PEERS") or "").strip()
        env_seed_peers_raw = (os.environ.get("WEALL_SEED_PEERS") or "").strip()
        env_peer_uris = _split_csv(env_peers_raw + "," + env_seed_peers_raw)
        if env_peer_uris:
            try:
                self._peers_store.merge(env_peer_uris, force=True)
            except Exception:
                pass

        self._seed_nodes = _split_csv(os.environ.get("WEALL_SEED_NODES", "") or os.environ.get("WEALL_SEED_URLS", ""))
        try:
            self._seed_discover_timeout_s = float(os.environ.get("WEALL_SEED_TIMEOUT_S", "2.0") or "2.0")
        except Exception:
            self._seed_discover_timeout_s = 2.0
        self._seed_discover_done = False

        self.node: Optional[NetNode] = None

        self._bft_timeout_seen: Dict[str, int] = {}
        self._bft_timeout_seen_ttl_ms: int = max(250, _env_int("WEALL_BFT_TIMEOUT_DEDUPE_TTL_MS", 10_000))

        self._tx_seen: Dict[str, int] = {}
        self._tx_seen_ttl_ms: int = max(1_000, _env_int("WEALL_NET_TX_DEDUPE_TTL_MS", 60_000))
        self._tx_gossip_interval_ms: int = max(25, _env_int("WEALL_NET_GOSSIP_TX_INTERVAL_MS", 250))
        self._tx_gossip_batch: int = max(1, _env_int("WEALL_NET_GOSSIP_TX_BATCH", 128))
        self._last_tx_gossip_ms: int = 0

        self._peers_max = max(1, _env_int("WEALL_PEERS_MAX", 64))
        self._dial_backoff: Dict[str, int] = {}
        self._dial_backoff_ms = max(250, _env_int("WEALL_DIAL_BACKOFF_MS", 1_000))
        self._dial_backoff_max_ms = max(self._dial_backoff_ms, _env_int("WEALL_DIAL_BACKOFF_MAX_MS", 15_000))

        self._bft_enabled = _env_bool("WEALL_BFT_ENABLED", False)

        self._bft_msg_seen: Dict[str, int] = {}
        self._bft_msg_seen_ttl_ms: int = max(250, _env_int("WEALL_BFT_MSG_DEDUPE_TTL_MS", 10_000))

        self._bft_propose_interval_ms = max(25, _env_int("WEALL_BFT_NET_PROPOSE_INTERVAL_MS", 250))
        self._bft_vote_interval_ms = max(25, _env_int("WEALL_BFT_NET_VOTE_INTERVAL_MS", 250))
        self._bft_timeout_interval_ms = max(25, _env_int("WEALL_BFT_NET_TIMEOUT_INTERVAL_MS", 250))
        self._last_bft_propose_ms: int = 0
        self._last_bft_vote_ms: int = 0
        self._last_bft_timeout_ms: int = 0

    def _state_snapshot(self) -> Json:
        try:
            st = self._executor.snapshot()
            if isinstance(st, dict):
                return st
        except Exception:
            pass
        return {}

    def _build_node(self) -> NetNode:
        chain_id = str(os.environ.get("WEALL_CHAIN_ID", "weall-devnet") or "weall-devnet").strip()
        schema_version = str(self._cfg.schema_version or "1").strip() or "1"

        tx_index_hash = "0"
        try:
            tx_index_hash = str(getattr(self._executor, "tx_index_hash", lambda: "0")() or "0")
        except Exception:
            tx_index_hash = "0"

        peer_id = str(os.environ.get("WEALL_PEER_ID", "") or "").strip() or "local"
        agent = str(os.environ.get("WEALL_AGENT", "weall-node") or "weall-node").strip() or "weall-node"

        id_pub = (os.environ.get("WEALL_NODE_PUBKEY") or os.environ.get("WEALL_IDENTITY_PUBKEY") or "").strip() or None
        id_priv = (os.environ.get("WEALL_NODE_PRIVKEY") or os.environ.get("WEALL_IDENTITY_PRIVKEY") or "").strip() or None

        cfg = NetConfig(
            chain_id=chain_id,
            schema_version=schema_version,
            tx_index_hash=tx_index_hash,
            peer_id=peer_id,
            agent=agent,
            caps=(),
            identity_pubkey=id_pub,
            identity_privkey=id_priv,
            server_cert=(os.environ.get("WEALL_NET_TLS_CERT") or None),
            server_key=(os.environ.get("WEALL_NET_TLS_KEY") or None),
        )

        sync = StateSyncService(chain_id=chain_id, snapshot_provider=self._state_snapshot)

        node = NetNode(
            cfg=cfg,
            on_tx=self._on_tx,
            on_bft_proposal=self._on_bft_proposal,
            on_bft_vote=self._on_bft_vote,
            on_bft_qc=self._on_bft_qc,
            on_bft_timeout=self._on_bft_timeout,
            ledger_provider=self._state_snapshot,
            sync_service=sync,
        )
        return node

    def _seed_discover_once(self) -> None:
        if self._seed_discover_done:
            return
        self._seed_discover_done = True

        if not self._seed_nodes:
            return

        learned: list[str] = []
        for seed in list(self._seed_nodes):
            url = _seed_net_self_url(seed)
            obj = _http_get_json(url, timeout_s=float(self._seed_discover_timeout_s))
            if not isinstance(obj, dict):
                continue
            net = obj.get("net") if isinstance(obj.get("net"), dict) else {}
            adv = str(net.get("advertise_uri") or "").strip()
            if adv and _is_peer_uri(adv):
                learned.append(adv)

        if learned:
            try:
                self._peers_store.merge(learned, force=True)
                try:
                    log_event(_LOG, "net_seed_discovery", learned=learned, count=len(learned))
                except Exception:
                    pass
            except Exception:
                pass

    def start(self) -> bool:
        if not self._cfg.enabled:
            return False
        if self._started:
            return False

        try:
            self.node = self._build_node()
        except Exception as e:
            try:
                log_event(_LOG, "net_start_failed", error=str(e))
            except Exception:
                pass
            return False

        try:
            self._seed_discover_once()
        except Exception:
            pass

        try:
            bind = PeerAddr(uri=f"tcp://{self._cfg.bind_host}:{int(self._cfg.bind_port)}")
            self.node.bind(bind)
        except Exception as e:
            try:
                log_event(_LOG, "net_bind_failed", error=str(e))
            except Exception:
                pass
            self.node = None
            return False

        self._stop.clear()
        self._t = threading.Thread(target=self._run, name="weall-net-loop", daemon=True)
        self._t.start()
        self._started = True
        return True

    def stop(self) -> None:
        self._stop.set()
        try:
            if self.node is not None:
                self.node.close()
        except Exception:
            pass

    def join(self, *, timeout: Optional[float] = None) -> None:
        t = self._t
        if t is None:
            return
        try:
            t.join(timeout=timeout)
        except Exception:
            return

    def _run(self) -> None:
        if self.node is None:
            return

        tick_s = max(0.005, float(self._cfg.tick_ms) / 1000.0)

        while not self._stop.is_set():
            try:
                self.node.poll()
            except Exception:
                pass

            try:
                self._dial_peers_tick()
            except Exception:
                pass

            try:
                self._outbound_tx_gossip_tick()
            except Exception:
                pass

            if self._bft_enabled:
                try:
                    self._outbound_bft_tick()
                except Exception:
                    pass

            time.sleep(tick_s)

    def _dial_peers_tick(self) -> None:
        if self.node is None:
            return

        now = _now_ms()
        peers: list[str] = []
        try:
            peers = [str(x) for x in (self._peers_store.read_list() or [])]
        except Exception:
            peers = []

        peers = [p.strip() for p in peers if isinstance(p, str) and p.strip()]
        peers = peers[: self._peers_max]

        for uri in peers:
            allow = int(self._dial_backoff.get(uri, 0))
            if allow > now:
                continue

            try:
                self.node.connect(PeerAddr(uri=uri))
                self._dial_backoff[uri] = 0
            except Exception:
                prev = max(self._dial_backoff_ms, int(self._dial_backoff.get(uri, 0) - now))
                nxt = min(self._dial_backoff_max_ms, max(self._dial_backoff_ms, prev * 2))
                self._dial_backoff[uri] = now + nxt

    # ----------------------------
    # Ingress handlers
    # ----------------------------

    def _on_tx(self, peer_id: str, msg: WireMessage) -> None:
        try:
            if not isinstance(msg, TxEnvelopeMsg):
                return

            tx = msg.tx
            if not isinstance(tx, dict):
                return

            # Signature policy mirrors HTTP boundary
            if _peer_requires_sigverify():
                ok = verify_tx_signature(tx)
                if not ok:
                    inc_counter("net_tx_reject_sigverify")
                    return

            # Apply the same admission rules as HTTP/mempool (nonce, gates, schema, etc.)
            try:
                st = self._state_snapshot()
                ledger = LedgerView.from_ledger(st if isinstance(st, dict) else {})
            except Exception:
                ledger = LedgerView.from_ledger({})

            canon = None
            try:
                canon = getattr(self._executor, "tx_index", None)
            except Exception:
                canon = None

            v = admit_tx(tx=tx, ledger=ledger, canon=canon, context="gossip")
            if not bool(v.ok):
                code = v.code or "reject"
                inc_counter(f"net_tx_reject_{code}")
                return

            # Submit to mempool (best-effort)
            try:
                self._mempool.add(tx)
            except Exception:
                pass
        except Exception:
            return

    def _mk_bft_proposal_json(self, msg: BftProposalMsg) -> Json:
        return {
            "view": int(getattr(msg, "view", 0) or 0),
            "proposer": str(getattr(msg, "proposer", "") or ""),
            "block": getattr(msg, "block", {}) or {},
            "justify_qc": getattr(msg, "justify_qc", None),
        }

    def _mk_bft_vote_json(self, msg: BftVoteMsg) -> Json:
        v = getattr(msg, "vote", {}) or {}
        if not isinstance(v, dict):
            v = {}
        if "view" not in v:
            v = dict(v)
            v["view"] = int(getattr(msg, "view", 0) or 0)
        return v

    def _mk_bft_timeout_json(self, msg: BftTimeoutMsg) -> Json:
        t = getattr(msg, "timeout", {}) or {}
        if not isinstance(t, dict):
            t = {}
        if "view" not in t:
            t = dict(t)
            t["view"] = int(getattr(msg, "view", 0) or 0)
        return t

    def _bft_timeout_key(self, msg: BftTimeoutMsg) -> str:
        try:
            t = getattr(msg, "timeout", None) or {}
            if isinstance(t, dict):
                view = str(t.get("view") or getattr(msg, "view", "") or "")
                signer = str(t.get("signer") or "")
                sig = str(t.get("sig") or "")
                high_qc_id = str(t.get("high_qc_id") or "")
                return f"{view}|{signer}|{sig}|{high_qc_id}"
        except Exception:
            pass
        try:
            return json.dumps(getattr(msg, "timeout", None), sort_keys=True, separators=(",", ":"))
        except Exception:
            return repr(getattr(msg, "timeout", None))

    def _bft_generic_key(self, payload: Any) -> str:
        try:
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))
        except Exception:
            return repr(payload)

    def _dedupe_seen(self, cache: Dict[str, int], key: str, *, ttl_ms: int, now_ms: int) -> bool:
        ttl = int(ttl_ms)
        if ttl <= 0:
            return False

        cutoff = int(now_ms) - ttl
        try:
            for k, ts in list(cache.items()):
                if int(ts) <= cutoff:
                    cache.pop(k, None)
        except Exception:
            pass

        if key in cache:
            return True
        cache[key] = int(now_ms)
        return False

    def _broadcast_bft_vote(self, vote_json: Json, *, exclude_peer_id: str = "") -> None:
        if self.node is None:
            return
        try:
            view = int(vote_json.get("view") or 0)
        except Exception:
            view = 0
        msg = BftVoteMsg(header=self._mk_header(mtype=MsgType.BFT_VOTE), view=view, vote=vote_json)
        try:
            self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
        except Exception:
            pass

    def _broadcast_bft_timeout(self, timeout_json: Json, *, exclude_peer_id: str = "") -> None:
        if self.node is None:
            return
        try:
            view = int(timeout_json.get("view") or 0)
        except Exception:
            view = 0
        msg = BftTimeoutMsg(header=self._mk_header(mtype=MsgType.BFT_TIMEOUT), view=view, timeout=timeout_json)
        try:
            self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
        except Exception:
            pass

    def _on_bft_proposal(self, peer_id: str, msg: BftProposalMsg) -> None:
        try:
            if not self._bft_enabled:
                return

            proposal = self._mk_bft_proposal_json(msg)

            now = _now_ms()
            key = self._bft_generic_key({"t": "proposal", "v": proposal})
            if self._dedupe_seen(self._bft_msg_seen, key, ttl_ms=self._bft_msg_seen_ttl_ms, now_ms=now):
                return

            fn = getattr(self._executor, "bft_on_proposal", None)
            if not callable(fn):
                return

            votej = fn(proposal)
            if isinstance(votej, dict) and votej:
                vote_key = self._bft_generic_key({"t": "vote", "v": votej})
                if not self._dedupe_seen(self._bft_msg_seen, vote_key, ttl_ms=self._bft_msg_seen_ttl_ms, now_ms=now):
                    self._broadcast_bft_vote(votej, exclude_peer_id=str(peer_id or ""))
        except Exception:
            return

    def _on_bft_qc(self, peer_id: str, msg: BftQcMsg) -> None:
        try:
            if not self._bft_enabled:
                return

            qcj = getattr(msg, "qc", {}) or {}
            if not isinstance(qcj, dict) or not qcj:
                return

            now = _now_ms()
            key = self._bft_generic_key({"t": "qc", "v": qcj})
            if self._dedupe_seen(self._bft_msg_seen, key, ttl_ms=self._bft_msg_seen_ttl_ms, now_ms=now):
                return

            fn = getattr(self._executor, "bft_on_qc", None)
            if callable(fn):
                fn(qcj)
        except Exception:
            return

    def _on_bft_timeout(self, peer_id: str, msg: BftTimeoutMsg) -> None:
        """Ingress handler for BFT timeouts.

        This is intentionally *always-on* when the net loop is running:
          - Timeouts are cheap and carry liveness information.
          - The loop dedupes to avoid amplification.
          - Tests rely on the loop re-broadcasting the exact received wire msg.

        We still best-effort notify the executor if it exposes bft_on_timeout.
        """

        try:
            now = _now_ms()
            key = self._bft_timeout_key(msg)
            if self._dedupe_seen(self._bft_timeout_seen, key, ttl_ms=self._bft_timeout_seen_ttl_ms, now_ms=now):
                return

            timeoutj = self._mk_bft_timeout_json(msg)

            try:
                fn = getattr(self._executor, "bft_on_timeout", None)
                if callable(fn):
                    fn(timeoutj)
            except Exception:
                pass

            if self.node is not None:
                try:
                    self.node.broadcast_message(msg, exclude_peer_id=str(peer_id or ""))
                except Exception:
                    pass
        except Exception:
            return

    # ----------------------------
    # Outbound TX gossip
    # ----------------------------

    def _mk_header(self, *, mtype: MsgType) -> WireHeader:
        assert self.node is not None
        cfg = self.node.cfg
        return WireHeader(type=mtype, chain_id=cfg.chain_id, schema_version=cfg.schema_version, tx_index_hash=cfg.tx_index_hash)

    def _tx_seen_prune(self, now_ms: int) -> None:
        cutoff = int(now_ms) - int(self._tx_seen_ttl_ms)
        try:
            for k, ts in list(self._tx_seen.items()):
                if int(ts) <= cutoff:
                    self._tx_seen.pop(k, None)
        except Exception:
            pass

    def _tx_seen_has(self, tx_id: str, now_ms: int) -> bool:
        self._tx_seen_prune(now_ms)
        if tx_id in self._tx_seen:
            return True
        self._tx_seen[tx_id] = int(now_ms)
        return False

    def _outbound_tx_gossip_tick(self) -> None:
        if self.node is None:
            return

        now = _now_ms()
        if (now - int(self._last_tx_gossip_ms)) < int(self._tx_gossip_interval_ms):
            return
        self._last_tx_gossip_ms = int(now)

        txs: list[Json] = []
        try:
            txs = list(self._mempool.peek(int(self._tx_gossip_batch)))  # type: ignore[attr-defined]
        except Exception:
            try:
                txs = list(getattr(self._mempool, "list", lambda *_a, **_k: [])())  # type: ignore[misc]
                txs = txs[: int(self._tx_gossip_batch)]
            except Exception:
                txs = []

        if not txs:
            return

        for tx in txs:
            if not isinstance(tx, dict):
                continue
            try:
                tx_id = compute_tx_id(tx)
            except Exception:
                tx_id = ""
            if not tx_id:
                continue
            if self._tx_seen_has(tx_id, now):
                continue

            msg = TxEnvelopeMsg(
                header=self._mk_header(mtype=MsgType.TX_ENVELOPE),
                tx=tx,
            )
            try:
                self.node.broadcast_message(msg)
            except Exception:
                pass

    # ----------------------------
    # Outbound BFT gossip
    # ----------------------------

    def _outbound_bft_tick(self) -> None:
        if self.node is None:
            return

        now = _now_ms()

        if (now - int(self._last_bft_propose_ms)) >= int(self._bft_propose_interval_ms):
            self._last_bft_propose_ms = int(now)
            try:
                out = getattr(self._executor, "bft_leader_propose", lambda: None)()
                if isinstance(out, dict):
                    if isinstance(out.get("proposal"), dict):
                        # Proposal broadcast handled by NetNode internally if needed
                        pass
            except Exception:
                pass

        if (now - int(self._last_bft_vote_ms)) >= int(self._bft_vote_interval_ms):
            self._last_bft_vote_ms = int(now)
            try:
                out = getattr(self._executor, "bft_drive_timeouts", lambda: None)()
                if isinstance(out, dict):
                    if isinstance(out.get("vote"), dict):
                        self._broadcast_bft_vote(out["vote"])
                    if isinstance(out.get("timeout"), dict):
                        self._broadcast_bft_timeout(out["timeout"])
            except Exception:
                pass

        if (now - int(self._last_bft_timeout_ms)) >= int(self._bft_timeout_interval_ms):
            self._last_bft_timeout_ms = int(now)
            try:
                out = getattr(self._executor, "bft_drive_timeouts", lambda: None)()
                if isinstance(out, dict):
                    if isinstance(out.get("timeout"), dict):
                        self._broadcast_bft_timeout(out["timeout"])
            except Exception:
                pass
