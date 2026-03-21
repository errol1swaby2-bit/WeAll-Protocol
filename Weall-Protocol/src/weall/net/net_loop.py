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
from typing import Any

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
from weall.runtime.mempool import compute_tx_id
from weall.runtime.metrics import inc_counter, set_gauge
from weall.runtime.protocol_profile import validate_runtime_consensus_profile
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_admission import admit_tx

Json = dict[str, Any]

_LOG = logging.getLogger("weall.net.loop")


class NetLoopRuntimeError(RuntimeError):
    pass


class NetStartupError(NetLoopRuntimeError):
    pass


class NetPeerConfigError(NetLoopRuntimeError):
    pass


class NetStateSnapshotError(NetLoopRuntimeError):
    pass


class TxIngressProcessingError(NetLoopRuntimeError):
    pass


class TxGossipBridgeError(NetLoopRuntimeError):
    pass


class BftInboundProcessingError(NetLoopRuntimeError):
    pass


class BftOutboundBridgeError(NetLoopRuntimeError):
    pass


class BftOutboundReplayError(BftOutboundBridgeError):
    pass


class BftFetchDescriptorError(NetLoopRuntimeError):
    pass


def _is_prod() -> bool:
    return _mode() == "prod"


def _raise_fail_closed(exc_type: type[Exception], reason: str) -> None:
    raise exc_type(reason)


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
    """Mirror HTTP boundary policy for peer-ingress.

    Production peer ingress must always require signatures; WEALL_SIGVERIFY
    may only tighten policy outside production, never relax it in prod.
    """

    mode = _mode()
    override = os.environ.get("WEALL_SIGVERIFY")
    if mode == "prod":
        return True
    if override is None:
        return False
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


def _http_get_json(url: str, *, timeout_s: float = 2.0) -> Json | None:
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


def _json_size_bytes(obj: Any, *, limit: int = 0) -> int:
    try:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        size = len(raw)
    except Exception:
        return -1
    if int(limit or 0) > 0 and size > int(limit):
        return size
    return size


def _payload_oversize(obj: Any, *, limit: int) -> bool:
    cap = int(limit or 0)
    if cap <= 0:
        return False
    size = _json_size_bytes(obj, limit=cap)
    return size < 0 or size > cap


def _required_keys_present(payload: Json, keys: tuple[str, ...]) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in keys:
        val = payload.get(key)
        if val in (None, "", []):
            return False
    return True


def _cheap_validate_bft_payload(kind: str, payload: Json, *, chain_id: str) -> str | None:
    if not isinstance(payload, dict) or not payload:
        return "empty_payload"
    expected_tag = {"proposal": None, "vote": "VOTE", "qc": None, "timeout": "TIMEOUT"}.get(kind)
    if expected_tag is not None and str(payload.get("t") or "").strip() != expected_tag:
        return "bad_type_tag"
    payload_chain_id = str(payload.get("chain_id") or chain_id).strip()
    if payload_chain_id != str(chain_id).strip():
        return "chain_mismatch"
    check_payload = payload
    if kind == "proposal":
        block = payload.get("block")
        if isinstance(block, dict) and block:
            check_payload = dict(block)
            if "view" not in check_payload and payload.get("view") not in (None, ""):
                check_payload["view"] = payload.get("view")
    required = {
        "proposal": ("block_id", "height", "view"),
        "vote": ("block_id", "parent_id", "view", "signer", "pubkey", "sig"),
        "qc": ("block_id", "view", "votes"),
        "timeout": ("view", "high_qc_id", "signer", "pubkey", "sig"),
    }[kind]
    if not _required_keys_present(check_payload, required):
        return "missing_required_fields"
    return None


def _emit_bft_rejection_diagnostic(
    executor: Any,
    message_type: str,
    payload: Json,
    reason: str,
    *,
    extra_summary: Json | None = None,
) -> None:
    try:
        if hasattr(executor, "_bft_record_event"):
            summary = {
                "view": int(payload.get("view") or 0) if isinstance(payload, dict) else 0,
                "block_id": str(payload.get("block_id") or "") if isinstance(payload, dict) else "",
                "signer": str(payload.get("signer") or payload.get("proposer") or "")
                if isinstance(payload, dict)
                else "",
                "validator_epoch": int(payload.get("validator_epoch") or 0)
                if isinstance(payload, dict)
                else 0,
                "validator_set_hash": str(payload.get("validator_set_hash") or "")
                if isinstance(payload, dict)
                else "",
                "high_qc_id": str(payload.get("high_qc_id") or "")
                if isinstance(payload, dict)
                else "",
            }
            if isinstance(extra_summary, dict):
                summary.update({str(k): v for k, v in extra_summary.items()})
            executor._bft_record_event(
                "bft_message_rejected",
                message_type=message_type,
                reason=reason,
                summary=summary,
            )
    except Exception:
        pass
    try:
        log_event("bft_message_rejected", message_type=message_type, reason=reason)
    except Exception:
        pass


@dataclass
class NetLoopConfig:
    enabled: bool
    bind_host: str
    bind_port: int
    tick_ms: int
    schema_version: str


def net_loop_config_from_env() -> NetLoopConfig:
    validate_runtime_consensus_profile()
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

    def __init__(self, *, executor, mempool, cfg: NetLoopConfig | None = None) -> None:
        self._executor = executor
        self._mempool = mempool
        self._cfg = cfg or net_loop_config_from_env()

        self._stop = threading.Event()
        self._t: threading.Thread | None = None
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
                if _is_prod():
                    raise NetStartupError("net_env_peer_merge_failed")

        self._seed_nodes = _split_csv(
            os.environ.get("WEALL_SEED_NODES", "") or os.environ.get("WEALL_SEED_URLS", "")
        )
        try:
            self._seed_discover_timeout_s = float(
                os.environ.get("WEALL_SEED_TIMEOUT_S", "2.0") or "2.0"
            )
        except Exception:
            self._seed_discover_timeout_s = 2.0
        self._seed_discover_done = False

        self.node: NetNode | None = None

        self._bft_timeout_seen: dict[str, int] = {}
        self._bft_timeout_seen_ttl_ms: int = max(
            250, _env_int("WEALL_BFT_TIMEOUT_DEDUPE_TTL_MS", 10_000)
        )
        self._bft_timeout_seen_max: int = max(32, _env_int("WEALL_BFT_TIMEOUT_DEDUPE_MAX", 4_096))

        self._tx_seen: dict[str, int] = {}
        self._tx_seen_ttl_ms: int = max(1_000, _env_int("WEALL_NET_TX_DEDUPE_TTL_MS", 60_000))
        self._tx_seen_max: int = max(128, _env_int("WEALL_NET_TX_DEDUPE_MAX", 16_384))
        self._tx_gossip_interval_ms: int = max(25, _env_int("WEALL_NET_GOSSIP_TX_INTERVAL_MS", 250))
        self._tx_gossip_batch: int = max(1, _env_int("WEALL_NET_GOSSIP_TX_BATCH", 128))
        self._last_tx_gossip_ms: int = 0

        self._peers_max = max(1, _env_int("WEALL_PEERS_MAX", 64))
        self._dial_backoff: dict[str, int] = {}
        self._dial_backoff_ms = max(250, _env_int("WEALL_DIAL_BACKOFF_MS", 1_000))
        self._dial_backoff_max_ms = max(
            self._dial_backoff_ms, _env_int("WEALL_DIAL_BACKOFF_MAX_MS", 15_000)
        )

        self._bft_enabled = _env_bool("WEALL_BFT_ENABLED", False)

        self._bft_msg_seen: dict[str, int] = {}
        self._bft_msg_seen_ttl_ms: int = max(250, _env_int("WEALL_BFT_MSG_DEDUPE_TTL_MS", 10_000))
        self._bft_msg_seen_max: int = max(128, _env_int("WEALL_BFT_MSG_DEDUPE_MAX", 16_384))

        self._bft_propose_interval_ms = max(25, _env_int("WEALL_BFT_NET_PROPOSE_INTERVAL_MS", 250))
        self._bft_vote_interval_ms = max(25, _env_int("WEALL_BFT_NET_VOTE_INTERVAL_MS", 250))
        self._bft_timeout_interval_ms = max(25, _env_int("WEALL_BFT_NET_TIMEOUT_INTERVAL_MS", 250))
        self._bft_fetch_enabled = _env_bool("WEALL_BFT_FETCH_ENABLED", True)
        self._bft_fetch_interval_ms = max(100, _env_int("WEALL_BFT_FETCH_INTERVAL_MS", 500))
        self._bft_fetch_cooldown_ms = max(250, _env_int("WEALL_BFT_FETCH_COOLDOWN_MS", 2_000))
        self._bft_fetch_batch = max(1, _env_int("WEALL_BFT_FETCH_BATCH", 8))
        self._bft_fetch_sources = _split_csv(os.environ.get("WEALL_BFT_FETCH_BASE_URLS", ""))
        self._bft_fetch_cooldowns: dict[str, int] = {}
        self._bft_fetch_source_penalty_ms = max(
            250, _env_int("WEALL_BFT_FETCH_SOURCE_PENALTY_MS", 5_000)
        )
        self._bft_fetch_source_cooldowns: dict[str, int] = {}
        self._bft_fetch_source_cursor: int = 0
        self._bft_fetch_source_penalty_drops: int = 0
        self._last_bft_fetch_ms: int = 0
        self._last_bft_propose_ms: int = 0
        self._last_bft_vote_ms: int = 0
        self._last_bft_timeout_ms: int = 0

        self._bft_proposal_max_bytes = max(
            1_024, _env_int("WEALL_BFT_PROPOSAL_MAX_BYTES", 1_048_576)
        )
        self._bft_vote_max_bytes = max(512, _env_int("WEALL_BFT_VOTE_MAX_BYTES", 131_072))
        self._bft_qc_max_bytes = max(1_024, _env_int("WEALL_BFT_QC_MAX_BYTES", 524_288))
        self._bft_timeout_max_bytes = max(512, _env_int("WEALL_BFT_TIMEOUT_MAX_BYTES", 131_072))
        self._bft_fetch_sources_max = max(1, _env_int("WEALL_BFT_FETCH_SOURCES_MAX", 16))

    def _state_snapshot(self) -> Json:
        try:
            st = self._executor.snapshot()
        except Exception:
            if _is_prod():
                raise NetStateSnapshotError("state_snapshot_failed")
            return {}
        if isinstance(st, dict):
            return st
        if _is_prod():
            raise NetStateSnapshotError("state_snapshot_invalid_type")
        return {}

    def _build_node(self) -> NetNode:
        executor_chain_id = str(getattr(self._executor, "chain_id", "") or "").strip()
        chain_id = (
            executor_chain_id
            or str(os.environ.get("WEALL_CHAIN_ID", "weall-devnet") or "weall-devnet").strip()
        )

        schema_version = str(self._cfg.schema_version or "1").strip() or "1"
        try:
            schema_version = (
                str(
                    getattr(self._executor, "_schema_version", lambda: schema_version)()
                    or schema_version
                ).strip()
                or schema_version
            )
        except Exception:
            schema_version = str(self._cfg.schema_version or "1").strip() or "1"

        tx_index_hash = "0"
        try:
            tx_index_hash = str(getattr(self._executor, "tx_index_hash", lambda: "0")() or "0")
        except Exception:
            if _is_prod():
                raise NetStartupError("net_build_node_tx_index_hash_failed")
            tx_index_hash = "0"

        peer_id = str(os.environ.get("WEALL_PEER_ID", "") or "").strip() or "local"
        agent = (
            str(os.environ.get("WEALL_AGENT", "weall-node") or "weall-node").strip() or "weall-node"
        )

        id_pub = (
            os.environ.get("WEALL_NODE_PUBKEY") or os.environ.get("WEALL_IDENTITY_PUBKEY") or ""
        ).strip() or None
        id_priv = (
            os.environ.get("WEALL_NODE_PRIVKEY") or os.environ.get("WEALL_IDENTITY_PRIVKEY") or ""
        ).strip() or None

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

        block_provider = getattr(self._executor, "get_block_by_height", None)
        if not callable(block_provider):
            block_provider = None
        sync = StateSyncService(
            chain_id=chain_id,
            schema_version=schema_version,
            tx_index_hash=tx_index_hash,
            state_provider=self._state_snapshot,
            block_provider=block_provider,
        )

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
            self.node = None
            return False

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

    def join(self, *, timeout: float | None = None) -> None:
        t = self._t
        if t is None:
            return
        try:
            t.join(timeout=timeout)
        except Exception as e:
            if _is_prod():
                raise BftInboundProcessingError("proposal_executor_failed") from e
            return

    def _run(self) -> None:
        if self.node is None:
            return

        tick_s = max(0.005, float(self._cfg.tick_ms) / 1000.0)

        while not self._stop.is_set():
            try:
                self.node.poll()
            except Exception:
                if _is_prod():
                    raise NetLoopRuntimeError("node_poll_failed")

            try:
                self._dial_peers_tick()
            except Exception:
                pass

            try:
                self._outbound_tx_gossip_tick()
            except Exception as e:
                if _is_prod():
                    raise NetLoopRuntimeError("tx_gossip_tick_failed") from e

            if self._bft_enabled:
                try:
                    self._bft_fetch_tick()
                except Exception:
                    pass
                try:
                    self._outbound_bft_tick()
                except Exception:
                    pass

            try:
                self._record_net_metric_gauges()
            except Exception:
                pass

            time.sleep(tick_s)

    def _dial_peers_tick(self) -> None:
        if self.node is None:
            return

        now = _now_ms()
        raw_peers = []
        try:
            raw_peers = list(self._peers_store.read_list() or [])
        except Exception as e:
            if _is_prod():
                raise NetPeerConfigError("peer_list_read_failed") from e
            raw_peers = []

        peers: list[str] = []
        for entry in raw_peers:
            if not isinstance(entry, str):
                if _is_prod():
                    raise NetPeerConfigError("peer_list_entry_invalid_type")
                continue
            uri = entry.strip()
            if not uri:
                continue
            if not _is_peer_uri(uri):
                if _is_prod():
                    raise NetPeerConfigError("peer_list_entry_invalid_uri")
                continue
            peers.append(uri)
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

            # Apply the same admission rules as HTTP/mempool (nonce, gates, schema, etc.)
            try:
                st = self._state_snapshot()
                ledger = LedgerView.from_ledger(st if isinstance(st, dict) else {})
            except Exception as e:
                if _is_prod():
                    raise TxIngressProcessingError("tx_ingress_state_snapshot_failed") from e
                st = {}
                ledger = LedgerView.from_ledger({})

            # Signature policy mirrors HTTP boundary
            if _peer_requires_sigverify():
                ok = verify_tx_signature(st if isinstance(st, dict) else {}, tx)
                if not ok:
                    inc_counter("net_tx_reject_sigverify")
                    return

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
            except Exception as e:
                if _is_prod():
                    raise TxIngressProcessingError("tx_ingress_mempool_add_failed") from e
        except Exception:
            if _is_prod():
                raise
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

    def _dedupe_seen(
        self, cache: dict[str, int], key: str, *, ttl_ms: int, now_ms: int, max_entries: int = 0
    ) -> bool:
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

        if int(max_entries or 0) > 0 and len(cache) >= int(max_entries):
            try:
                overflow = (len(cache) - int(max_entries)) + 1
                oldest = sorted(cache.items(), key=lambda kv: (int(kv[1]), str(kv[0])))[:overflow]
                for old_key, _ in oldest:
                    cache.pop(old_key, None)
            except Exception:
                try:
                    cache.pop(next(iter(cache)), None)
                except Exception:
                    pass

        cache[key] = int(now_ms)
        return False

    def _record_net_metric_gauges(self) -> None:
        try:
            set_gauge("net_bft_seen_cache", len(self._bft_msg_seen))
            set_gauge("net_bft_timeout_seen_cache", len(self._bft_timeout_seen))
            set_gauge("net_tx_seen_cache", len(self._tx_seen))
            set_gauge("net_bft_fetch_cooldowns", len(self._bft_fetch_cooldowns))
            set_gauge("net_peers_configured", len(list(self._peers_store.read_list() or [])))
        except Exception:
            pass
        try:
            diag = getattr(self._executor, "bft_diagnostics", lambda: {})() or {}
            if isinstance(diag, dict):
                set_gauge(
                    "net_bft_pending_remote_blocks",
                    len(list(diag.get("pending_remote_blocks") or [])),
                )
                set_gauge(
                    "net_bft_pending_missing_qcs", len(list(diag.get("pending_missing_qcs") or []))
                )
                set_gauge(
                    "net_bft_pending_fetch_requests",
                    len(list(diag.get("pending_fetch_requests") or [])),
                )
        except Exception:
            pass

    def _bft_payload_limit(self, kind: str) -> int:
        return {
            "proposal": int(self._bft_proposal_max_bytes),
            "vote": int(self._bft_vote_max_bytes),
            "qc": int(self._bft_qc_max_bytes),
            "timeout": int(self._bft_timeout_max_bytes),
        }.get(str(kind or ""), 0)

    def _bft_payload_reject_reason(self, kind: str, payload: Json) -> str | None:
        limit = self._bft_payload_limit(kind)
        if _payload_oversize(payload, limit=limit):
            inc_counter(f"net_bft_{kind}_reject_oversize")
            return "oversize_payload"
        return None

    def _executor_bft_current_view(self) -> int:
        try:
            fn = getattr(self._executor, "bft_current_view", None)
            if callable(fn):
                return int(fn() or 0)
        except Exception:
            return 0
        return 0

    def _executor_bft_current_validator_epoch(self) -> int:
        try:
            fn = getattr(self._executor, "bft_current_validator_epoch", None)
            if callable(fn):
                return int(fn() or 0)
        except Exception:
            return 0
        return 0

    def _bft_prefilter_reject_reason(
        self, kind: str, payload: Json
    ) -> tuple[str | None, Json | None]:
        if not isinstance(payload, dict) or not payload:
            return (None, None)
        local_view = int(self._executor_bft_current_view())
        local_epoch = int(self._executor_bft_current_validator_epoch())
        payload_view = int(payload.get("view") or 0)
        payload_epoch = int(payload.get("validator_epoch") or 0)
        extra_summary = {
            "local_view": int(local_view),
            "local_validator_epoch": int(local_epoch),
        }
        if local_epoch > 0 and payload_epoch > 0 and payload_epoch < local_epoch:
            inc_counter(f"net_bft_{kind}_reject_stale_epoch")
            return ("stale_epoch", extra_summary)
        if local_view <= 0 or payload_view <= 0:
            return (None, extra_summary)
        stale = False
        if str(kind) == "timeout":
            stale = int(payload_view) + 1 < int(local_view)
        else:
            stale = int(payload_view) + 2 < int(local_view)
        if stale:
            inc_counter(f"net_bft_{kind}_reject_stale_view")
            return ("stale_view", extra_summary)
        return (None, extra_summary)

    def _bft_fetch_base_urls(self) -> list[str]:
        urls = [str(x).rstrip("/") for x in list(self._bft_fetch_sources or []) if str(x).strip()]
        if not urls:
            urls = [str(x).rstrip("/") for x in list(self._seed_nodes or []) if str(x).strip()]
        deduped: list[str] = []
        seen: set[str] = set()
        for url in urls:
            if not url or url in seen:
                continue
            seen.add(url)
            deduped.append(url)
            if len(deduped) >= int(self._bft_fetch_sources_max):
                break
        return deduped

    def _fetch_committed_block(self, base_url: str, block_id: str) -> Json | None:
        base = str(base_url or "").strip().rstrip("/")
        bid = str(block_id or "").strip()
        if not base or not bid:
            return None
        obj = _http_get_json(f"{base}/v1/state/block/{bid}", timeout_s=2.0)
        if not isinstance(obj, dict) or not bool(obj.get("ok")):
            return None
        blk = obj.get("block")
        return dict(blk) if isinstance(blk, dict) else None

    def _penalize_bft_fetch_source(self, base_url: str, *, now_ms: int | None = None) -> None:
        base = str(base_url or "").strip().rstrip("/")
        if not base:
            return
        now = int(_now_ms() if now_ms is None else now_ms)
        self._bft_fetch_source_cooldowns[base] = int(now) + int(self._bft_fetch_source_penalty_ms)
        self._bft_fetch_source_penalty_drops = int(self._bft_fetch_source_penalty_drops) + 1

    def _candidate_bft_fetch_sources(self, *, now_ms: int | None = None) -> list[str]:
        now = int(_now_ms() if now_ms is None else now_ms)
        sources = self._bft_fetch_base_urls()
        if not sources:
            return []
        total = len(sources)
        start = int(self._bft_fetch_source_cursor or 0) % total
        self._bft_fetch_source_cursor = int((start + 1) % total)
        ordered = [sources[(start + i) % total] for i in range(total)]
        active: list[str] = []
        for base in ordered:
            allow_at = int(self._bft_fetch_source_cooldowns.get(base, 0) or 0)
            if allow_at > now:
                continue
            active.append(base)
        return active

    def _bft_fetch_tick(self) -> None:
        if not self._bft_fetch_enabled:
            return
        now = _now_ms()
        if (now - int(self._last_bft_fetch_ms)) < int(self._bft_fetch_interval_ms):
            return
        self._last_bft_fetch_ms = int(now)
        raw_wants = []
        try:
            desc_fn = getattr(
                self._executor, "bft_resolved_pending_fetch_request_descriptors", None
            )
            if callable(desc_fn):
                raw_wants = list(desc_fn() or [])
            else:
                desc_fn = getattr(self._executor, "bft_pending_fetch_request_descriptors", None)
                if callable(desc_fn):
                    raw_wants = list(desc_fn() or [])
                else:
                    raw_wants = list(
                        getattr(self._executor, "bft_pending_fetch_requests", lambda: [])() or []
                    )
        except Exception as e:
            if _is_prod():
                raise BftFetchDescriptorError("descriptor_resolution_failed") from e
            raw_wants = []
        wants: list[dict[str, str]] = []
        for item in raw_wants:
            try:
                resolver = getattr(self._executor, "bft_resolve_fetch_request_descriptor", None)
                if callable(resolver) and isinstance(item, dict):
                    resolved = resolver(item)
                    if resolved is not None:
                        item = resolved
                if isinstance(item, dict):
                    bid = str(item.get("block_id") or "").strip()
                    if not bid:
                        continue
                    wants.append(
                        {
                            "block_id": bid,
                            "block_hash": str(item.get("block_hash") or "").strip(),
                            "reason": str(item.get("reason") or "").strip(),
                        }
                    )
                else:
                    bid = str(item or "").strip()
                    if not bid:
                        continue
                    wants.append({"block_id": bid, "block_hash": "", "reason": ""})
            except Exception as e:
                if _is_prod():
                    raise BftFetchDescriptorError("descriptor_resolution_failed") from e
        if not wants:
            self._record_net_metric_gauges()
            return
        sources = self._bft_fetch_base_urls()
        if not sources:
            inc_counter("net_bft_fetch_no_sources")
            self._record_net_metric_gauges()
            return
        sent = 0
        for req in wants:
            sbid = str((req or {}).get("block_id") or "").strip()
            expected_hash = str((req or {}).get("block_hash") or "").strip()
            if not sbid:
                continue
            allow_at = int(self._bft_fetch_cooldowns.get(sbid, 0) or 0)
            if allow_at > now:
                continue
            self._bft_fetch_cooldowns[sbid] = int(now) + int(self._bft_fetch_cooldown_ms)
            for base in self._candidate_bft_fetch_sources(now_ms=now):
                blk = self._fetch_committed_block(base, sbid)
                if not isinstance(blk, dict):
                    inc_counter("net_bft_fetch_miss")
                    continue
                if str(blk.get("block_id") or "").strip() != sbid:
                    try:
                        log_event(
                            _LOG,
                            "bft_fetch_block_id_mismatch",
                            requested_block_id=sbid,
                            returned_block_id=str(blk.get("block_id") or ""),
                            base_url=base,
                        )
                    except Exception:
                        pass
                    self._penalize_bft_fetch_source(base, now_ms=now)
                    continue
                fetched_hash = str(
                    blk.get("block_hash")
                    or (
                        (blk.get("header") or {}) if isinstance(blk.get("header"), dict) else {}
                    ).get("block_hash")
                    or ""
                ).strip()
                if expected_hash and fetched_hash and fetched_hash != expected_hash:
                    try:
                        log_event(
                            _LOG,
                            "bft_fetch_block_hash_mismatch",
                            requested_block_id=sbid,
                            expected_block_hash=expected_hash,
                            returned_block_hash=fetched_hash,
                            base_url=base,
                        )
                    except Exception:
                        pass
                    self._penalize_bft_fetch_source(base, now_ms=now)
                    inc_counter("net_bft_fetch_hash_mismatch")
                    continue
                try:
                    ok = bool(
                        getattr(self._executor, "bft_cache_remote_block", lambda *_a, **_k: False)(
                            blk
                        )
                    )
                except Exception as e:
                    if _is_prod():
                        raise BftFetchDescriptorError("cache_remote_block_failed") from e
                    ok = False
                if ok:
                    inc_counter("net_bft_fetch_applied")
                    try:
                        log_event(_LOG, "bft_fetch_applied", block_id=sbid, base_url=base)
                    except Exception:
                        pass
                    sent += 1
                    break
                inc_counter("net_bft_fetch_reject")
            if sent >= int(self._bft_fetch_batch):
                break
        self._record_net_metric_gauges()

    def _mark_bft_outbound_sent(self, kind: str, payload: Json) -> None:
        try:
            fn = getattr(self._executor, "bft_mark_outbound_sent", None)
            if callable(fn):
                fn(str(kind), payload)
        except Exception as e:
            if _is_prod():
                raise BftOutboundBridgeError(f"mark_outbound_sent_failed:{str(kind)}") from e
            return

    def _broadcast_bft_proposal(self, proposal_json: Json, *, exclude_peer_id: str = "") -> None:
        if self.node is None or not isinstance(proposal_json, dict) or not proposal_json:
            return

        block = (
            proposal_json.get("block")
            if isinstance(proposal_json.get("block"), dict)
            else proposal_json
        )
        if not isinstance(block, dict) or not block:
            return

        justify_qc = proposal_json.get("justify_qc")
        if not isinstance(justify_qc, dict):
            justify_qc = (
                block.get("justify_qc")
                if isinstance(block.get("justify_qc"), dict)
                else block.get("qc")
            )
        try:
            view = int(
                proposal_json.get("view")
                or block.get("view")
                or getattr(self._executor, "bft_current_view", lambda: 0)()
                or 0
            )
        except Exception:
            view = 0
        proposer = str(
            proposal_json.get("proposer")
            or block.get("proposer")
            or getattr(self.node.cfg, "peer_id", "")
            or ""
        ).strip()
        msg = BftProposalMsg(
            header=self._mk_header(mtype=MsgType.BFT_PROPOSAL),
            view=view,
            proposer=proposer,
            block=block,
            justify_qc=justify_qc if isinstance(justify_qc, dict) else None,
        )
        try:
            self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
            self._mark_bft_outbound_sent("proposal", block)
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftOutboundBridgeError):
                    raise
                raise BftOutboundBridgeError("proposal_broadcast_failed") from e

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
            self._mark_bft_outbound_sent("vote", vote_json)
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftOutboundBridgeError):
                    raise
                raise BftOutboundBridgeError("vote_broadcast_failed") from e

    def _broadcast_bft_timeout(self, timeout_json: Json, *, exclude_peer_id: str = "") -> None:
        if self.node is None:
            return
        try:
            view = int(timeout_json.get("view") or 0)
        except Exception:
            view = 0
        msg = BftTimeoutMsg(
            header=self._mk_header(mtype=MsgType.BFT_TIMEOUT), view=view, timeout=timeout_json
        )
        try:
            self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
            self._mark_bft_outbound_sent("timeout", timeout_json)
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftOutboundBridgeError):
                    raise
                raise BftOutboundBridgeError("timeout_broadcast_failed") from e

    def _on_bft_proposal(self, peer_id: str, msg: BftProposalMsg) -> None:
        try:
            if not self._bft_enabled:
                return

            proposal = self._mk_bft_proposal_json(msg)

            now = _now_ms()
            key = self._bft_generic_key({"t": "proposal", "v": proposal})
            if self._dedupe_seen(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_msg_seen_max,
            ):
                inc_counter("net_bft_proposal_duplicate")
                return

            local_chain_id = str(
                getattr(getattr(self.node, "cfg", None), "chain_id", "")
                or getattr(getattr(msg, "header", None), "chain_id", "")
                or ""
            )
            reason = self._bft_payload_reject_reason(
                "proposal", proposal
            ) or _cheap_validate_bft_payload("proposal", proposal, chain_id=local_chain_id)
            prefilter_reason, prefilter_summary = self._bft_prefilter_reject_reason(
                "proposal", proposal
            )
            reason = reason or prefilter_reason
            if reason is not None:
                inc_counter("net_bft_proposal_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor,
                    "proposal",
                    proposal,
                    reason,
                    extra_summary=prefilter_summary,
                )
                return

            fn = getattr(self._executor, "bft_on_proposal", None)
            if not callable(fn):
                return

            votej = fn(proposal)
            if votej is None:
                inc_counter("net_bft_proposal_executor_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor, "proposal", proposal, "executor_rejected"
                )
                return
            if isinstance(votej, dict) and votej:
                vote_key = self._bft_generic_key({"t": "vote", "v": votej})
                if not self._dedupe_seen(
                    self._bft_msg_seen,
                    vote_key,
                    ttl_ms=self._bft_msg_seen_ttl_ms,
                    now_ms=now,
                    max_entries=self._bft_msg_seen_max,
                ):
                    self._broadcast_bft_vote(votej, exclude_peer_id=str(peer_id or ""))
            self._record_net_metric_gauges()
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftInboundProcessingError):
                    raise
                raise BftInboundProcessingError("proposal_executor_failed") from e
            return

    def _on_bft_vote(self, peer_id: str, msg: BftVoteMsg) -> None:
        try:
            if not self._bft_enabled:
                return

            votej = self._mk_bft_vote_json(msg)
            if not isinstance(votej, dict) or not votej:
                return

            now = _now_ms()
            key = self._bft_generic_key({"t": "vote", "v": votej})
            if self._dedupe_seen(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_msg_seen_max,
            ):
                inc_counter("net_bft_vote_duplicate")
                return

            local_chain_id = str(
                getattr(getattr(self.node, "cfg", None), "chain_id", "")
                or getattr(getattr(msg, "header", None), "chain_id", "")
                or ""
            )
            reason = self._bft_payload_reject_reason("vote", votej) or _cheap_validate_bft_payload(
                "vote", votej, chain_id=local_chain_id
            )
            prefilter_reason, prefilter_summary = self._bft_prefilter_reject_reason("vote", votej)
            reason = reason or prefilter_reason
            if reason is not None:
                inc_counter("net_bft_vote_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor,
                    "vote",
                    votej,
                    reason,
                    extra_summary=prefilter_summary,
                )
                return

            fn = getattr(self._executor, "bft_on_vote", None)
            if not callable(fn):
                return

            qcj = fn(votej)
            if qcj is None:
                inc_counter("net_bft_vote_executor_rejected")
                _emit_bft_rejection_diagnostic(self._executor, "vote", votej, "executor_rejected")
                return
            if isinstance(qcj, dict) and qcj:
                try:
                    apply_fn = getattr(self._executor, "bft_on_qc", None)
                    if callable(apply_fn):
                        apply_fn(qcj)
                except Exception as e:
                    if _is_prod():
                        raise BftInboundProcessingError("vote_local_qc_apply_failed") from e
                qc_key = self._bft_generic_key({"t": "qc", "v": qcj})
                if not self._dedupe_seen(
                    self._bft_msg_seen,
                    qc_key,
                    ttl_ms=self._bft_msg_seen_ttl_ms,
                    now_ms=now,
                    max_entries=self._bft_msg_seen_max,
                ):
                    qmsg = BftQcMsg(header=self._mk_header(mtype=MsgType.BFT_QC), qc=qcj)
                    try:
                        self.node.broadcast_message(qmsg, exclude_peer_id=str(peer_id or ""))
                    except Exception as e:
                        if _is_prod():
                            raise BftInboundProcessingError("vote_qc_broadcast_failed") from e
            self._record_net_metric_gauges()
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftInboundProcessingError):
                    raise
                raise BftInboundProcessingError("vote_executor_failed") from e
            return

    def _on_bft_qc(self, peer_id: str, msg: BftQcMsg) -> None:
        try:
            if not self._bft_enabled:
                return

            qcj = getattr(msg, "qc", {}) or {}
            if not isinstance(qcj, dict) or not qcj:
                return

            local_chain_id = str(
                getattr(getattr(self.node, "cfg", None), "chain_id", "")
                or getattr(getattr(msg, "header", None), "chain_id", "")
                or ""
            )
            reason = self._bft_payload_reject_reason("qc", qcj) or _cheap_validate_bft_payload(
                "qc", qcj, chain_id=local_chain_id
            )
            prefilter_reason, prefilter_summary = self._bft_prefilter_reject_reason("qc", qcj)
            reason = reason or prefilter_reason
            if reason is not None:
                inc_counter("net_bft_qc_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor,
                    "qc",
                    qcj,
                    reason,
                    extra_summary=prefilter_summary,
                )
                return

            now = _now_ms()
            key = self._bft_generic_key({"t": "qc", "v": qcj})
            if self._dedupe_seen(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_msg_seen_max,
            ):
                inc_counter("net_bft_qc_duplicate")
                return

            fn = getattr(self._executor, "bft_on_qc", None)
            if callable(fn):
                out = fn(qcj)
                if out is None:
                    inc_counter("net_bft_qc_executor_rejected")
                    _emit_bft_rejection_diagnostic(self._executor, "qc", qcj, "executor_rejected")
            self._record_net_metric_gauges()
        except Exception as e:
            if _is_prod():
                raise BftInboundProcessingError("qc_executor_failed") from e
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
            if self._dedupe_seen(
                self._bft_timeout_seen,
                key,
                ttl_ms=self._bft_timeout_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_timeout_seen_max,
            ):
                inc_counter("net_bft_timeout_duplicate")
                return

            timeoutj = self._mk_bft_timeout_json(msg)
            local_chain_id = str(
                getattr(getattr(self.node, "cfg", None), "chain_id", "")
                or getattr(getattr(msg, "header", None), "chain_id", "")
                or ""
            )
            reason = self._bft_payload_reject_reason(
                "timeout", timeoutj
            ) or _cheap_validate_bft_payload("timeout", timeoutj, chain_id=local_chain_id)
            prefilter_reason, prefilter_summary = self._bft_prefilter_reject_reason(
                "timeout", timeoutj
            )
            reason = reason or prefilter_reason
            if reason is not None:
                inc_counter("net_bft_timeout_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor,
                    "timeout",
                    timeoutj,
                    reason,
                    extra_summary=prefilter_summary,
                )
                return

            out = None
            fn = getattr(self._executor, "bft_on_timeout", None)
            if callable(fn):
                out = fn(timeoutj)
                if out is None:
                    inc_counter("net_bft_timeout_executor_rejected")
                    _emit_bft_rejection_diagnostic(
                        self._executor, "timeout", timeoutj, "executor_rejected"
                    )
            if isinstance(out, dict) and out:
                try:
                    apply_fn = getattr(self._executor, "bft_on_qc", None)
                    if callable(apply_fn):
                        apply_fn(out)
                except Exception as e:
                    if _is_prod():
                        raise BftInboundProcessingError("timeout_local_qc_apply_failed") from e

            if self.node is not None:
                try:
                    self.node.broadcast_message(msg, exclude_peer_id=str(peer_id or ""))
                except Exception as e:
                    if _is_prod():
                        raise BftInboundProcessingError("timeout_broadcast_failed") from e
            self._record_net_metric_gauges()
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftInboundProcessingError):
                    raise
                raise BftInboundProcessingError("timeout_executor_failed") from e
            return

    # ----------------------------
    # Outbound TX gossip
    # ----------------------------

    def _mk_header(self, *, mtype: MsgType) -> WireHeader:
        assert self.node is not None
        cfg = self.node.cfg
        return WireHeader(
            type=mtype,
            chain_id=cfg.chain_id,
            schema_version=cfg.schema_version,
            tx_index_hash=cfg.tx_index_hash,
        )

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
        if int(self._tx_seen_max or 0) > 0 and len(self._tx_seen) >= int(self._tx_seen_max):
            try:
                overflow = (len(self._tx_seen) - int(self._tx_seen_max)) + 1
                oldest = sorted(self._tx_seen.items(), key=lambda kv: (int(kv[1]), str(kv[0])))[
                    :overflow
                ]
                for old_key, _ in oldest:
                    self._tx_seen.pop(old_key, None)
            except Exception:
                try:
                    self._tx_seen.pop(next(iter(self._tx_seen)), None)
                except Exception:
                    pass
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
            except Exception as e:
                if _is_prod():
                    raise TxGossipBridgeError("tx_gossip_source_failed") from e
                txs = []

        if not txs:
            return

        for tx in txs:
            if not isinstance(tx, dict):
                if _is_prod():
                    raise TxGossipBridgeError("tx_gossip_entry_not_object")
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
                nonce=int(tx.get("nonce") or 0) if isinstance(tx, dict) else 0,
                client_tx_id=str(tx.get("client_tx_id") or "")
                if isinstance(tx, dict) and tx.get("client_tx_id") is not None
                else None,
                tx=tx,
            )
            try:
                self.node.broadcast_message(msg)
            except Exception as e:
                if _is_prod():
                    raise TxGossipBridgeError("tx_gossip_broadcast_failed") from e

    # ----------------------------
    # Outbound BFT gossip
    # ----------------------------

    def _outbound_bft_tick(self) -> None:
        if self.node is None:
            return

        try:
            pending = getattr(self._executor, "bft_pending_outbound_messages", lambda: [])()
        except Exception:
            pending = []
        for item in list(pending or []):
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "").strip().lower()
            payload = item.get("payload")
            if not isinstance(payload, dict) or not payload:
                if _is_prod():
                    raise BftOutboundReplayError("invalid_payload")
                continue
            if kind == "vote":
                self._broadcast_bft_vote(payload)
            elif kind == "timeout":
                self._broadcast_bft_timeout(payload)
            elif kind == "proposal":
                self._broadcast_bft_proposal(payload)

        now = _now_ms()

        if (now - int(self._last_bft_propose_ms)) >= int(self._bft_propose_interval_ms):
            self._last_bft_propose_ms = int(now)
            try:
                out = getattr(self._executor, "bft_leader_propose", lambda: None)()
                if isinstance(out, dict) and out:
                    self._broadcast_bft_proposal(out)
            except Exception as e:
                if _is_prod():
                    if isinstance(e, BftOutboundBridgeError):
                        raise
                    raise BftOutboundBridgeError("leader_propose_failed") from e

        if (now - int(self._last_bft_vote_ms)) >= int(self._bft_vote_interval_ms):
            self._last_bft_vote_ms = int(now)
            try:
                out = getattr(self._executor, "bft_drive_timeouts", lambda *_a, **_k: None)(now)
            except TypeError:
                try:
                    out = getattr(self._executor, "bft_drive_timeouts", lambda: None)()
                except Exception:
                    out = None
            except Exception as e:
                if _is_prod():
                    raise BftOutboundBridgeError("drive_timeouts_failed") from e
                out = None
            try:
                if isinstance(out, list):
                    for item in out:
                        if isinstance(item, dict) and item:
                            self._broadcast_bft_timeout(item)
                elif isinstance(out, dict):
                    if isinstance(out.get("vote"), dict):
                        self._broadcast_bft_vote(out["vote"])
                    if isinstance(out.get("timeout"), dict):
                        self._broadcast_bft_timeout(out["timeout"])
            except Exception as e:
                if _is_prod():
                    if isinstance(e, BftOutboundBridgeError):
                        raise
                    raise BftOutboundBridgeError("drive_timeouts_failed") from e
                pass

        if (now - int(self._last_bft_timeout_ms)) >= int(self._bft_timeout_interval_ms):
            self._last_bft_timeout_ms = int(now)
            try:
                out = getattr(self._executor, "bft_timeout_check", lambda: None)()
                if isinstance(out, dict) and out:
                    self._broadcast_bft_timeout(out)
            except Exception as e:
                if _is_prod():
                    raise BftOutboundBridgeError("timeout_check_failed") from e
