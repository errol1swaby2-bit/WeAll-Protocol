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

import inspect
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from weall.api.public_seed_registry import (
    PublicSeedRegistryError,
    load_public_seed_registry,
    public_seed_registry_path,
    public_testnet_enabled,
    verified_peer_uris_from_registry,
)
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
from weall.net.peer_store import PeerSecurityStore
from weall.net.relay import (
    RelayConfig,
    RelayEnvelopeError,
    decode_relay_payload,
    make_relay_access_request,
    make_relay_envelope,
    validate_relay_envelope,
)
from weall.net.state_sync import StateSyncService
from weall.net.transport import PeerAddr
from weall.runtime.mempool import compute_tx_id
from weall.runtime.metrics import inc_counter, set_gauge
from weall.runtime.protocol_profile import validate_runtime_consensus_profile
from weall.runtime.runtime_authority import effective_bft_enabled
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


def _call_with_optional_now_once(fn: Any, now_ms: int) -> Any:
    """Invoke a compatibility callable exactly once.

    Signature adaptation is decided before the call so an internal ``TypeError``
    can never be mistaken for an old zero-argument API and retried.
    """

    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(now_ms)

    params = tuple(signature.parameters.values())
    accepts_positional = any(
        param.kind is inspect.Parameter.VAR_POSITIONAL for param in params
    ) or any(
        param.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for param in params
    )
    return fn(now_ms) if accepts_positional else fn()


def _is_prod() -> bool:
    return _mode() == "prod"


def _raise_fail_closed(exc_type: type[Exception], reason: str) -> None:
    raise exc_type(reason)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _interval_due_or_clock_rollback(*, now_ms: int, last_ms: int, interval_ms: int) -> bool:
    """Return whether a local scheduler interval is due.

    These timestamps are deliberately node-local and non-consensus. A backwards
    host-clock adjustment must re-arm work instead of suppressing it until the prior
    wall-clock value is reached again.
    """
    now = int(now_ms)
    last = int(last_ms)
    interval = max(0, int(interval_ms))
    if last <= 0:
        return True
    if now < last:
        return True
    return (now - last) >= interval


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
    # Runtime posture is explicit; production code never infers pytest state.
    # Tests set WEALL_MODE=test in their harness when non-production behavior is required.
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


def _public_registry_peer_uris() -> list[str]:
    if not public_testnet_enabled():
        return []
    try:
        registry = load_public_seed_registry(public_seed_registry_path())
    except PublicSeedRegistryError as exc:
        if _is_prod():
            raise NetStartupError(str(exc) or "public_seed_registry_error") from exc
        return []
    peers = verified_peer_uris_from_registry(registry, include_seeds=True, include_validators=True)
    return [uri for uri in peers if _is_peer_uri(uri)]


def _seed_net_self_url(seed: str) -> str:
    s = str(seed or "").strip()
    if not s:
        return ""
    # Allow passing a full /v1/net/self URL or a base URL.
    if "/v1/net/self" in s:
        return s
    s = s.rstrip("/")
    return f"{s}/v1/net/self"


def _http_get_json(
    url: str, *, timeout_s: float = 2.0, headers: dict[str, str] | None = None
) -> Json | None:
    if not url:
        return None
    try:
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update({str(k): str(v) for k, v in headers.items() if str(v).strip()})
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            data = resp.read()
        obj = json.loads(data.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None
    except Exception:
        return None


def _peer_state_raw_read_headers() -> dict[str, str]:
    token = str(
        os.environ.get("WEALL_PEER_STATE_RAW_READ_TOKEN")
        or os.environ.get("WEALL_STATE_RAW_READ_TOKEN")
        or os.environ.get("WEALL_STATE_SYNC_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OPERATOR_TOKEN")
        or ""
    ).strip()
    if not token:
        return {}
    return {
        "X-WeAll-State-Raw-Read-Token": token,
        "X-WeAll-State-Sync-Operator-Token": token,
    }


def _http_post_json(url: str, obj: Json, *, timeout_s: float = 2.0) -> Json | None:
    if not url:
        return None
    try:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=raw,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            data = resp.read()
        parsed = json.loads(data.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
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
        self._runtime_unhealthy = False
        self._runtime_last_error = ""
        self._runtime_failure_count = 0

        peers_file = os.environ.get("WEALL_PEERS_FILE", "./data/peers.json")
        self._peers_store = PeerListStore(path=str(peers_file or "./data/peers.json"))

        env_peers_raw = (os.environ.get("WEALL_PEERS") or "").strip()
        env_seed_peers_raw = (os.environ.get("WEALL_SEED_PEERS") or "").strip()
        env_peer_uris = _split_csv(env_peers_raw + "," + env_seed_peers_raw)
        public_registry_peers = _public_registry_peer_uris()
        if public_registry_peers:
            env_peer_uris.extend(public_registry_peers)
        if env_peer_uris:
            try:
                self._peers_store.merge(env_peer_uris, force=True)
            except Exception:
                if _is_prod():
                    raise NetStartupError("net_env_peer_merge_failed")

        self._seed_nodes = _split_csv(
            os.environ.get("WEALL_SEED_NODES", "") or os.environ.get("WEALL_SEED_URLS", "")
        )
        if public_testnet_enabled():
            try:
                registry = load_public_seed_registry(public_seed_registry_path())
                self._seed_nodes.extend(
                    str(url) for url in registry.get("seed_api_urls", []) if str(url).strip()
                )
            except PublicSeedRegistryError as exc:
                if _is_prod():
                    raise NetStartupError(str(exc) or "public_seed_registry_error") from exc
        try:
            self._seed_discover_timeout_s = float(
                os.environ.get("WEALL_SEED_TIMEOUT_S", "2.0") or "2.0"
            )
        except Exception:
            self._seed_discover_timeout_s = 2.0
        self._seed_discover_done = False
        # Public observers need discovery to self-heal after seed/validator endpoint
        # churn. A zero value preserves the old one-shot behavior outside public
        # testnet unless explicitly configured.
        self._seed_discovery_refresh_ms = max(
            0,
            _env_int(
                "WEALL_SEED_DISCOVERY_REFRESH_MS",
                60_000 if public_testnet_enabled() else 0,
            ),
        )
        self._last_seed_discover_ms = 0
        self._seed_discovery_last_ok = False
        self._seed_discovery_last_learned = 0
        self._seed_discovery_last_error = ""

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
        self._addr_gossip_interval_ms = max(
            250, _env_int("WEALL_NET_ADDR_GOSSIP_INTERVAL_MS", 30_000)
        )
        self._last_addr_gossip_ms = 0

        self._bft_enabled = bool(
            effective_bft_enabled(
                executor=self._executor, default=_env_bool("WEALL_BFT_ENABLED", False)
            )
        )

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

        # Production-safe outbound relay polling/submission for NAT/CGNAT nodes.
        # Relays are transport-only mailboxes; relayed messages still pass normal
        # tx/BFT admission when consumed. Disabled by default.
        self._relay_client_enabled = _env_bool("WEALL_NET_RELAY_CLIENT_ENABLED", False)
        self._relay_urls = [
            u.rstrip("/")
            for u in _split_csv(os.environ.get("WEALL_NET_RELAY_URLS", ""))
            if u.strip()
        ]
        self._relay_recipients = _split_csv(os.environ.get("WEALL_NET_RELAY_RECIPIENTS", ""))
        self._relay_poll_ms = max(250, _env_int("WEALL_NET_RELAY_POLL_MS", 1_000))
        self._relay_fetch_limit = max(1, _env_int("WEALL_NET_RELAY_CLIENT_FETCH_LIMIT", 50))
        self._relay_timeout_s = max(
            0.25, float(_env_int("WEALL_NET_RELAY_TIMEOUT_MS", 2_000)) / 1000.0
        )
        self._relay_ttl_ms = max(1_000, _env_int("WEALL_NET_RELAY_ENVELOPE_TTL_MS", 60_000))
        self._relay_last_poll_ms = 0
        self._relay_seen: dict[str, int] = {}
        self._relay_bft_ack_guards: dict[str, tuple[str, Json]] = {}
        self._relay_seen_ttl_ms = max(
            10_000, _env_int("WEALL_NET_RELAY_DEDUPE_TTL_MS", 10 * 60 * 1000)
        )
        self._relay_seen_max = max(128, _env_int("WEALL_NET_RELAY_DEDUPE_MAX", 16_384))
        self._relay_nonce = 0
        self._bft_branch_generation_seen = self._executor_bft_branch_generation()
        if self._relay_client_enabled and _is_prod():
            if not self._relay_urls:
                raise NetStartupError("net_relay_client_enabled_without_urls")
            if not (os.environ.get("WEALL_NODE_PUBKEY") or os.environ.get("WEALL_IDENTITY_PUBKEY")):
                raise NetStartupError("net_relay_client_missing_pubkey")
            if not (
                os.environ.get("WEALL_NODE_PRIVKEY") or os.environ.get("WEALL_IDENTITY_PRIVKEY")
            ):
                raise NetStartupError("net_relay_client_missing_privkey")

    def _state_snapshot(self) -> Json:
        try:
            st = self._executor.read_state()
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
            bft_enabled=bool(self._bft_enabled),
            advertise_uri=(
                os.environ.get("WEALL_NET_ADVERTISE_URI")
                or os.environ.get("WEALL_NET_PUBLIC_URI")
                or None
            ),
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
            bft_enabled=bool(self._bft_enabled),
        )

        peer_security_store = None
        aux_db = getattr(self._executor, "_aux_db", None)
        if aux_db is not None:
            peer_security_store = PeerSecurityStore(db=aux_db)

        node = NetNode(
            cfg=cfg,
            on_tx=self._on_tx,
            on_bft_proposal=self._on_bft_proposal,
            on_bft_vote=self._on_bft_vote,
            on_bft_qc=self._on_bft_qc,
            on_bft_timeout=self._on_bft_timeout,
            on_peer_addr_records=self._on_peer_addr_records,
            peer_addr_provider=self._peer_addr_provider,
            ledger_provider=self._state_snapshot,
            sync_service=sync,
            peer_security_store=peer_security_store,
        )
        return node

    def _seed_discover_once(self, *, force: bool = False) -> None:
        if self._seed_discover_done and not force:
            return
        self._seed_discover_done = True
        self._last_seed_discover_ms = _now_ms()
        self._seed_discovery_last_ok = False
        self._seed_discovery_last_learned = 0
        self._seed_discovery_last_error = ""

        if not self._seed_nodes:
            self._seed_discovery_last_error = "no_seed_nodes_configured"
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
                self._seed_discovery_last_ok = True
                self._seed_discovery_last_learned = len(learned)
                try:
                    log_event(
                        _LOG,
                        "net_seed_discovery",
                        learned=learned,
                        count=len(learned),
                        refresh=bool(force),
                    )
                except Exception:
                    pass
            except Exception:
                self._seed_discovery_last_error = "peer_store_merge_failed"
                if _is_prod():
                    raise NetPeerConfigError("peer_store_merge_failed")
        else:
            self._seed_discovery_last_error = "no_advertise_uri_learned"

    def _seed_discovery_tick(self) -> None:
        if int(self._seed_discovery_refresh_ms or 0) <= 0:
            return
        now = _now_ms()
        if (now - int(self._last_seed_discover_ms or 0)) < int(self._seed_discovery_refresh_ms):
            return
        self._seed_discover_once(force=True)

    def seed_discovery_debug(self) -> Json:
        return {
            "seed_nodes_configured": len(list(self._seed_nodes or [])),
            "refresh_ms": int(self._seed_discovery_refresh_ms or 0),
            "last_refresh_ms": int(self._last_seed_discover_ms or 0),
            "last_ok": bool(self._seed_discovery_last_ok),
            "last_learned": int(self._seed_discovery_last_learned or 0),
            "last_error": str(self._seed_discovery_last_error or ""),
        }

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
        self._t = threading.Thread(target=self._thread_main, name="weall-net-loop", daemon=True)
        self._started = True
        try:
            self._t.start()
        except Exception:
            self._started = False
            raise
        return True

    def runtime_debug(self) -> Json:
        thread = self._t
        return {
            "started": bool(self._started),
            "thread_alive": bool(thread is not None and thread.is_alive()),
            "unhealthy": bool(self._runtime_unhealthy),
            "last_error": str(self._runtime_last_error or ""),
            "failure_count": int(self._runtime_failure_count),
        }

    def _thread_main(self) -> None:
        """Run the mesh loop with fail-fast visibility but without silent thread death.

        ``_run`` intentionally raises production-critical network/BFT failures.
        A daemon-thread target must record that failure before retrying; otherwise
        the process can keep serving HTTP while networking has died and still look
        started to operators.  The unhealthy latch remains set until process restart.
        """

        try:
            while not self._stop.is_set():
                try:
                    self._run()
                    break
                except Exception as exc:
                    self._runtime_unhealthy = True
                    self._runtime_failure_count += 1
                    self._runtime_last_error = f"{type(exc).__name__}:{exc}"
                    try:
                        log_event(
                            _LOG,
                            "net_runtime_failed",
                            error=self._runtime_last_error,
                            failure_count=int(self._runtime_failure_count),
                        )
                    except Exception:
                        pass
                    # Keep polling/recovery possible after a surfaced liveness
                    # failure.  The health latch remains degraded until restart.
                    if self._stop.wait(max(0.05, float(self._cfg.tick_ms) / 1000.0)):
                        break
        finally:
            self._started = False

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
                self._seed_discovery_tick()
            except Exception as e:
                if _is_prod():
                    if isinstance(e, NetLoopRuntimeError):
                        raise
                    raise NetPeerConfigError("seed_discovery_tick_failed") from e

            try:
                self._dial_peers_tick()
            except Exception as e:
                if _is_prod():
                    if isinstance(e, NetLoopRuntimeError):
                        raise
                    raise NetPeerConfigError("dial_peers_tick_failed") from e

            try:
                self._addr_gossip_tick()
            except Exception as e:
                if _is_prod():
                    if isinstance(e, NetLoopRuntimeError):
                        raise
                    raise NetPeerConfigError("addr_gossip_tick_failed") from e

            try:
                self._relay_poll_tick()
            except Exception as e:
                if _is_prod():
                    raise NetLoopRuntimeError("relay_poll_tick_failed") from e

            try:
                self._outbound_tx_gossip_tick()
            except Exception as e:
                if _is_prod():
                    raise NetLoopRuntimeError("tx_gossip_tick_failed") from e

            if self._bft_enabled:
                try:
                    self._bft_fetch_tick()
                except Exception as e:
                    if _is_prod():
                        if isinstance(e, NetLoopRuntimeError):
                            raise
                        raise BftInboundProcessingError("bft_fetch_tick_failed") from e
                try:
                    self._outbound_bft_tick()
                except Exception as e:
                    if _is_prod():
                        if isinstance(e, NetLoopRuntimeError):
                            raise
                        raise BftOutboundBridgeError("bft_outbound_tick_failed") from e

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

    def _peer_addr_provider(self) -> list[str]:
        try:
            peers = list(self._peers_store.read_list() or [])
        except Exception:
            return []
        out: list[str] = []
        seen: set[str] = set()
        for entry in peers:
            if not isinstance(entry, str):
                continue
            uri = entry.strip()
            if not uri or not _is_peer_uri(uri) or uri in seen:
                continue
            seen.add(uri)
            out.append(uri)
            if len(out) >= int(self._peers_max):
                break
        return out

    def _on_peer_addr_records(self, _peer_id: str, records: tuple[Json, ...]) -> None:
        learned: list[str] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            uri = str(rec.get("uri") or "").strip()
            if uri and _is_peer_uri(uri):
                learned.append(uri)
        if not learned:
            return
        try:
            self._peers_store.merge(learned, force=False)
            try:
                log_event(_LOG, "net_addr_gossip_learned", count=len(learned))
            except Exception:
                pass
        except Exception:
            if _is_prod():
                raise NetPeerConfigError("peer_addr_gossip_merge_failed")

    def _addr_gossip_tick(self) -> None:
        if self.node is None:
            return
        now = _now_ms()
        if (now - int(self._last_addr_gossip_ms or 0)) < int(self._addr_gossip_interval_ms):
            return
        self._last_addr_gossip_ms = now
        try:
            self.node.broadcast_peer_addr()
        except Exception:
            if _is_prod():
                raise
            return

    # ----------------------------
    # Outbound HTTP relay client
    # ----------------------------

    def _relay_cfg(self) -> RelayConfig | None:
        if self.node is None:
            return None
        return RelayConfig(
            chain_id=str(self.node.cfg.chain_id),
            schema_version=str(self.node.cfg.schema_version),
            tx_index_hash=str(self.node.cfg.tx_index_hash),
            max_payload_bytes=max(1_024, _env_int("WEALL_NET_RELAY_MAX_PAYLOAD_BYTES", 512 * 1024)),
            max_ttl_ms=max(1_000, _env_int("WEALL_NET_RELAY_MAX_TTL_MS", 10 * 60 * 1000)),
            max_fetch_limit=max(1, int(self._relay_fetch_limit)),
            require_recipient_pubkey=_is_prod(),
        )

    def _relay_identity(self) -> tuple[str, str]:
        pub = (
            os.environ.get("WEALL_NODE_PUBKEY") or os.environ.get("WEALL_IDENTITY_PUBKEY") or ""
        ).strip()
        priv = (
            os.environ.get("WEALL_NODE_PRIVKEY") or os.environ.get("WEALL_IDENTITY_PRIVKEY") or ""
        ).strip()
        return pub, priv

    def _relay_next_nonce(self) -> str:
        self._relay_nonce += 1
        peer_id = str(getattr(getattr(self.node, "cfg", None), "peer_id", "") or "local")
        return f"{peer_id}:{int(_now_ms())}:{int(self._relay_nonce)}"

    def _relay_recipient_pubkey(self, recipient: str) -> str:
        """Return an optional relay-recipient pubkey for mailbox binding.

        Preferred production config is JSON: {"peer-id":"mldsa-pubkey"} in
        WEALL_NET_RELAY_RECIPIENT_PUBKEYS. If the recipient itself is a 64-char
        hex key, it can also be used directly for key-addressed relay mailboxes.
        """
        rid = str(recipient or "").strip()
        raw = (os.environ.get("WEALL_NET_RELAY_RECIPIENT_PUBKEYS") or "").strip()
        if raw:
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    pk = str(obj.get(rid) or "").strip()
                    if pk:
                        return pk
            except Exception:
                if _is_prod():
                    raise NetStartupError("net_relay_bad_recipient_pubkey_map")
        if len(rid) == 64 and all(c in "0123456789abcdefABCDEF" for c in rid):
            return rid.lower()
        return ""

    def _relay_submit_message(
        self, msg: WireMessage, *, recipients: list[str] | tuple[str, ...] | None = None
    ) -> None:
        if not self._relay_client_enabled or self.node is None or not self._relay_urls:
            return
        cfg = self._relay_cfg()
        if cfg is None:
            return
        pub, priv = self._relay_identity()
        if not pub or not priv:
            if _is_prod():
                raise NetStartupError("net_relay_client_missing_identity")
            return
        targets = [
            str(x or "").strip()
            for x in list(recipients or self._relay_recipients or [])
            if str(x or "").strip()
        ]
        if not targets:
            return
        sender = str(getattr(self.node.cfg, "peer_id", "") or "local").strip() or "local"
        for recipient in targets:
            try:
                recipient_pubkey = self._relay_recipient_pubkey(recipient)
                if bool(cfg.require_recipient_pubkey) and recipient != "*" and not recipient_pubkey:
                    raise NetStartupError("net_relay_missing_recipient_pubkey")
                env = make_relay_envelope(
                    message=msg,
                    chain_id=cfg.chain_id,
                    schema_version=cfg.schema_version,
                    tx_index_hash=cfg.tx_index_hash,
                    sender_peer_id=sender,
                    recipient_peer_id=recipient,
                    recipient_pubkey=recipient_pubkey,
                    pubkey=pub,
                    privkey=priv,
                    nonce=self._relay_next_nonce(),
                    ttl_ms=int(self._relay_ttl_ms),
                )
            except Exception as e:
                if _is_prod():
                    raise NetLoopRuntimeError("relay_envelope_build_failed") from e
                continue
            for base in list(self._relay_urls):
                _http_post_json(
                    f"{base}/v1/net/relay/submit",
                    {"envelope": env},
                    timeout_s=float(self._relay_timeout_s),
                )

    def _relay_access_request(
        self, request_type: str, peer_id: str, *, relay_ids: list[str] | None = None
    ) -> Json | None:
        cfg = self._relay_cfg()
        if cfg is None:
            return None
        pub, priv = self._relay_identity()
        if not pub or not priv:
            if _is_prod():
                raise NetStartupError("net_relay_client_missing_identity")
            return None
        return make_relay_access_request(
            request_type=request_type,
            chain_id=cfg.chain_id,
            schema_version=cfg.schema_version,
            tx_index_hash=cfg.tx_index_hash,
            recipient_peer_id=str(peer_id),
            pubkey=pub,
            privkey=priv,
            nonce=self._relay_next_nonce(),
            relay_ids=relay_ids or [],
            limit=int(self._relay_fetch_limit),
            ttl_ms=int(self._relay_ttl_ms),
        )

    def _relay_fetch(self, base: str, peer_id: str) -> Json | None:
        req = self._relay_access_request("fetch", peer_id)
        if not isinstance(req, dict):
            return None
        return _http_post_json(
            f"{str(base).rstrip('/')}/v1/net/relay/fetch",
            {"access_request": req},
            timeout_s=float(self._relay_timeout_s),
        )

    def _relay_ack(self, base: str, peer_id: str, relay_ids: list[str]) -> None:
        if not relay_ids:
            return
        req = self._relay_access_request("ack", peer_id, relay_ids=relay_ids)
        if not isinstance(req, dict):
            return
        _http_post_json(
            f"{str(base).rstrip('/')}/v1/net/relay/ack",
            {"access_request": req},
            timeout_s=float(self._relay_timeout_s),
        )

    def _relay_process_envelope(self, envelope: Json) -> bool:
        self._sync_bft_branch_generation()
        cfg = self._relay_cfg()
        if cfg is None:
            return False
        env = validate_relay_envelope(envelope, cfg=cfg)
        rid = str(env.get("relay_id") or "")
        now = _now_ms()
        msg = decode_relay_payload(env)
        sender = str(env.get("sender_peer_id") or "relay-peer")
        is_bft = isinstance(msg, (BftProposalMsg, BftVoteMsg, BftQcMsg, BftTimeoutMsg))

        if rid:
            if is_bft:
                # Consensus artifacts are retryable until the authenticated runtime
                # path accepts them. Merely fetching a relay envelope is not a trust
                # event and must not suppress an exact later delivery.
                if self._seen_contains(
                    self._relay_seen,
                    rid,
                    ttl_ms=int(self._relay_seen_ttl_ms),
                    now_ms=now,
                ):
                    return True
            elif self._dedupe_seen(
                self._relay_seen,
                rid,
                ttl_ms=int(self._relay_seen_ttl_ms),
                now_ms=now,
                max_entries=int(self._relay_seen_max),
            ):
                return True

        if isinstance(msg, TxEnvelopeMsg):
            self._on_tx(sender, msg)
            return True

        accepted = False
        if isinstance(msg, BftProposalMsg):
            accepted = bool(self._on_bft_proposal(sender, msg))
        elif isinstance(msg, BftVoteMsg):
            accepted = bool(self._on_bft_vote(sender, msg))
        elif isinstance(msg, BftQcMsg):
            accepted = bool(self._on_bft_qc(sender, msg))
        elif isinstance(msg, BftTimeoutMsg):
            accepted = bool(self._on_bft_timeout(sender, msg))
        else:
            # Non-consensus peer utility messages are accepted as delivered but do
            # not mutate chain state through relay polling.
            return True

        if not accepted:
            return False
        if rid and is_bft:
            guard = self._bft_relay_guard_payload(msg)
            if guard is None:
                return False
            kind, payload = guard

            def _record_relay_acceptance() -> None:
                self._dedupe_seen(
                    self._relay_seen,
                    rid,
                    ttl_ms=int(self._relay_seen_ttl_ms),
                    now_ms=now,
                    max_entries=int(self._relay_seen_max),
                )
                self._relay_bft_ack_guards[rid] = (str(kind), dict(payload))
                while len(self._relay_bft_ack_guards) > int(self._relay_seen_max):
                    oldest = next(iter(self._relay_bft_ack_guards), "")
                    if not oldest:
                        break
                    self._relay_bft_ack_guards.pop(oldest, None)

            if not self._run_postauth_bft_side_effect_if_current(
                kind,
                payload,
                _record_relay_acceptance,
            ):
                inc_counter("net_relay_bft_postauth_branch_drop")
                return False
        elif rid:
            self._dedupe_seen(
                self._relay_seen,
                rid,
                ttl_ms=int(self._relay_seen_ttl_ms),
                now_ms=now,
                max_entries=int(self._relay_seen_max),
            )
        return True

    def _relay_poll_tick(self) -> None:
        if not self._relay_client_enabled or self.node is None or not self._relay_urls:
            return
        now = _now_ms()
        if (now - int(self._relay_last_poll_ms or 0)) < int(self._relay_poll_ms):
            return
        self._relay_last_poll_ms = now
        peer_id = str(getattr(self.node.cfg, "peer_id", "") or "").strip()
        if not peer_id:
            return
        for base in list(self._relay_urls):
            obj = self._relay_fetch(base, peer_id)
            if not isinstance(obj, dict) or not bool(obj.get("ok")):
                continue
            messages = obj.get("messages")
            if not isinstance(messages, list):
                continue
            ack_ids: list[str] = []
            for env in messages:
                if not isinstance(env, dict):
                    continue
                try:
                    if self._relay_process_envelope(env):
                        rid = str(env.get("relay_id") or "").strip()
                        if rid:
                            ack_ids.append(rid)
                except RelayEnvelopeError:
                    # Ack malformed stored envelopes to prevent infinite replay.
                    rid = str(env.get("relay_id") or "").strip()
                    if rid:
                        ack_ids.append(rid)
                    continue
            if not ack_ids:
                # Preserve the existing no-op call contract used by focused relay
                # tests and compatibility shims.
                self._relay_ack(base, peer_id, [])
                continue

            plain_ack_ids: list[str] = []
            for rid in ack_ids:
                guard = self._relay_bft_ack_guards.get(rid)
                if guard is None:
                    plain_ack_ids.append(rid)
                    continue
                kind, payload = guard

                def _ack_one(
                    relay_id: str = rid,
                    relay_base: str = base,
                    relay_peer_id: str = peer_id,
                ) -> None:
                    self._relay_ack(relay_base, relay_peer_id, [relay_id])

                if self._run_postauth_bft_side_effect_if_current(kind, payload, _ack_one):
                    self._relay_bft_ack_guards.pop(rid, None)
                else:
                    inc_counter("net_relay_bft_ack_postauth_branch_drop")

            if plain_ack_ids:
                self._relay_ack(base, peer_id, plain_ack_ids)

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

            # Submit to mempool (best-effort). Persist the local admission height
            # as protocol metadata so block-candidate eligibility is anchored to
            # candidate height rather than wall-clock expiry.
            try:
                current_height = 0
                if isinstance(st, dict):
                    try:
                        current_height = int(st.get("height") or 0)
                    except Exception:
                        current_height = 0
                self._mempool.add(tx, current_height=current_height)
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
        timeoutj = self._mk_bft_timeout_json(msg)
        return self._bft_network_dedupe_key("timeout", timeoutj)

    def _bft_generic_key(self, payload: Any) -> str:
        try:
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))
        except Exception:
            return repr(payload)

    def _executor_bft_branch_generation(self) -> int:
        fn = getattr(self._executor, "bft_branch_generation", None)
        if not callable(fn):
            return 0
        try:
            return max(0, int(fn() or 0))
        except Exception:
            if _is_prod():
                raise NetLoopRuntimeError("bft_branch_generation_read_failed")
            return 0

    def _sync_bft_branch_generation(self) -> bool:
        """Invalidate branch-sensitive network caches after destructive reset."""
        current = self._executor_bft_branch_generation()
        previous = max(0, int(getattr(self, "_bft_branch_generation_seen", 0) or 0))
        if current == previous:
            return False

        # These caches encode prior branch-local handling/gossip truth. The
        # executor clears the corresponding runtime/persistent truth at the
        # checkpoint boundary; retaining network copies could otherwise suppress
        # fresh branch-B admission or propagation with branch-A evidence.
        self._bft_msg_seen.clear()
        self._bft_timeout_seen.clear()
        self._relay_seen.clear()
        self._relay_bft_ack_guards.clear()
        self._tx_seen.clear()
        # Missing-block requests are derived from branch-local BFT identity truth.
        # A checkpoint invalidates both their per-block cooldowns and the fetch
        # scheduler timestamp so the adopted branch can immediately request its
        # own missing dependencies. Source penalties are transport-quality state
        # and intentionally survive branch replacement.
        self._bft_fetch_cooldowns.clear()
        self._last_bft_fetch_ms = 0
        self._bft_branch_generation_seen = current
        inc_counter("net_bft_branch_dedupe_reset")
        inc_counter("net_tx_branch_dedupe_reset")
        inc_counter("net_bft_fetch_branch_reset")
        return True

    def _bft_network_dedupe_key(self, kind: str, payload: Json) -> str:
        """Prefer runtime canonical BFT identity after authenticated admission.

        The cache is populated only after runtime acceptance, so computing this
        key before verification cannot poison retries. Test doubles and older
        executors fall back to the exact wire representation.
        """
        fn = getattr(self._executor, "bft_artifact_dedupe_key", None)
        if callable(fn):
            try:
                semantic_key = str(fn(str(kind), payload) or "").strip()
            except Exception:
                semantic_key = ""
            if semantic_key:
                return f"semantic:{str(kind).strip().lower()}:{semantic_key}"
        return self._bft_generic_key({"t": str(kind), "v": payload})

    def _bft_runtime_accepted(self, kind: str, payload: Json, result: Any) -> bool:
        """Return whether runtime authenticated/admitted an inbound BFT artifact."""
        fn = getattr(self._executor, "bft_artifact_was_accepted", None)
        if callable(fn):
            try:
                return bool(fn(str(kind), payload))
            except Exception:
                if _is_prod():
                    raise
                return False
        # Compatibility for test doubles and non-runtime executors.
        return result is not None

    def _run_postauth_bft_side_effect_if_current(
        self,
        kind: str,
        payload: Json,
        side_effect,
    ) -> bool:
        """Run a post-authentication BFT side effect under branch authority.

        Production WeAllExecutor holds the canonical-branch lock while it
        revalidates that the artifact is still admitted and runs ``side_effect``.
        This prevents a destructive checkpoint from landing between admission
        and transport-visible work such as re-gossip or relay acknowledgement.
        """
        guarded = getattr(self._executor, "bft_run_postauth_side_effect_if_current", None)
        if callable(guarded):
            try:
                return bool(guarded(str(kind), payload, side_effect))
            except Exception:
                if _is_prod():
                    raise
                return False

        # Compatibility for focused non-production test doubles. Production
        # WeAllExecutor exposes the branch-guarded API.
        if _is_prod():
            raise NetLoopRuntimeError("bft_postauth_branch_guard_missing")
        side_effect()
        return True

    def _bft_relay_guard_payload(self, msg: object) -> tuple[str, Json] | None:
        if isinstance(msg, BftProposalMsg):
            payload = self._mk_bft_proposal_json(msg)
            return ("proposal", payload) if isinstance(payload, dict) and payload else None
        if isinstance(msg, BftVoteMsg):
            payload = self._mk_bft_vote_json(msg)
            return ("vote", payload) if isinstance(payload, dict) and payload else None
        if isinstance(msg, BftQcMsg):
            payload = getattr(msg, "qc", {}) or {}
            return ("qc", payload) if isinstance(payload, dict) and payload else None
        if isinstance(msg, BftTimeoutMsg):
            payload = self._mk_bft_timeout_json(msg)
            return ("timeout", payload) if isinstance(payload, dict) and payload else None
        return None

    def _seen_contains(self, cache: dict[str, int], key: str, *, ttl_ms: int, now_ms: int) -> bool:
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
        return key in cache

    def _dedupe_seen(
        self, cache: dict[str, int], key: str, *, ttl_ms: int, now_ms: int, max_entries: int = 0
    ) -> bool:
        if self._seen_contains(cache, key, ttl_ms=ttl_ms, now_ms=now_ms):
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
        url = f"{base}/v1/state/block/{bid}"
        headers = _peer_state_raw_read_headers()
        try:
            obj = _http_get_json(url, timeout_s=2.0, headers=headers)
        except TypeError as exc:
            # Several older unit tests monkeypatch _http_get_json with a narrow
            # `(url, *, timeout_s=...)` callable. Preserve that test seam while
            # still sending auth headers through the real helper in production.
            if headers or "headers" not in str(exc):
                raise
            obj = _http_get_json(url, timeout_s=2.0)
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
                # A normal source penalty can only be at most one configured penalty
                # window into the future. A larger gap means the wall clock moved
                # backwards after the cooldown was recorded; clear that local penalty
                # rather than black-holing this source until the old clock catches up.
                if (allow_at - now) <= int(self._bft_fetch_source_penalty_ms):
                    continue
                self._bft_fetch_source_cooldowns.pop(base, None)
            active.append(base)
        return active

    def _bft_fetch_tick(self) -> None:
        if not self._bft_fetch_enabled:
            return
        # Re-arm branch-local fetch state before the interval/cooldown gates.
        # Otherwise a recent branch-A fetch can suppress the first branch-B fetch
        # after destructive checkpoint replacement.
        self._sync_bft_branch_generation()
        fetch_generation = self._executor_bft_branch_generation()
        now = _now_ms()
        if not _interval_due_or_clock_rollback(
            now_ms=now,
            last_ms=int(self._last_bft_fetch_ms),
            interval_ms=int(self._bft_fetch_interval_ms),
        ):
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
                # As with per-source penalties, an allowance farther into the future
                # than one configured cooldown window indicates a backwards host-clock
                # adjustment. Re-arm the missing-block fetch rather than suppressing it
                # until the previous wall-clock value is reached again.
                if (allow_at - now) <= int(self._bft_fetch_cooldown_ms):
                    continue
                self._bft_fetch_cooldowns.pop(sbid, None)
            self._bft_fetch_cooldowns[sbid] = int(now) + int(self._bft_fetch_cooldown_ms)
            for base in self._candidate_bft_fetch_sources(now_ms=now):
                if self._executor_bft_branch_generation() != fetch_generation:
                    self._sync_bft_branch_generation()
                    inc_counter("net_bft_fetch_discarded_branch_change")
                    self._record_net_metric_gauges()
                    return
                blk = self._fetch_committed_block(base, sbid)
                # The HTTP request can outlive a destructive checkpoint. Never
                # let a response derived from branch-A descriptor truth reach the
                # branch-B cache boundary.
                if self._executor_bft_branch_generation() != fetch_generation:
                    self._sync_bft_branch_generation()
                    inc_counter("net_bft_fetch_discarded_branch_change")
                    self._record_net_metric_gauges()
                    return
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
                    cache_remote = getattr(
                        self._executor, "bft_cache_remote_block", lambda *_a, **_k: False
                    )
                    try:
                        ok = bool(
                            cache_remote(
                                blk,
                                expected_block_hash=expected_hash,
                                expected_branch_generation=fetch_generation,
                            )
                        )
                    except TypeError:
                        # Test doubles and older non-production adapters may not
                        # expose the generation-aware keyword yet. Production still
                        # fails closed through the established cache_remote_block_failed
                        # contract; only non-production compatibility paths may fall
                        # back after rechecking the branch generation.
                        if _is_prod():
                            raise
                        if self._executor_bft_branch_generation() != fetch_generation:
                            ok = False
                        else:
                            ok = bool(
                                cache_remote(
                                    blk,
                                    expected_block_hash=expected_hash,
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

    def _send_local_bft_artifact_if_current(self, kind: str, payload: Json, send_fn) -> bool:
        """Serialize a local BFT transport send against destructive branch reset."""
        guarded = getattr(self._executor, "bft_send_local_artifact_if_current", None)
        if callable(guarded):
            try:
                ok = bool(guarded(str(kind), payload, send_fn))
            except Exception as e:
                if _is_prod():
                    raise BftOutboundBridgeError(f"branch_guarded_send_failed:{str(kind)}") from e
                return False
            if not ok:
                inc_counter("net_bft_stale_local_artifact_drop")
            return ok

        # Compatibility path for focused test doubles and legacy non-production
        # executors. The production WeAllExecutor exposes the guarded API.
        send_fn()
        if str(kind) in {"proposal", "vote", "timeout"}:
            self._mark_bft_outbound_sent(str(kind), payload)
        return True

    def _broadcast_bft_proposal(self, proposal_json: Json, *, exclude_peer_id: str = "") -> None:
        self._sync_bft_branch_generation()
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

            def _send() -> None:
                self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
                self._relay_submit_message(msg)

            self._send_local_bft_artifact_if_current("proposal", block, _send)
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftOutboundBridgeError):
                    raise
                raise BftOutboundBridgeError("proposal_broadcast_failed") from e

    def _broadcast_bft_vote(self, vote_json: Json, *, exclude_peer_id: str = "") -> None:
        self._sync_bft_branch_generation()
        if self.node is None:
            return
        try:
            view = int(vote_json.get("view") or 0)
        except Exception:
            view = 0
        msg = BftVoteMsg(header=self._mk_header(mtype=MsgType.BFT_VOTE), view=view, vote=vote_json)
        try:

            def _send() -> None:
                self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
                self._dedupe_seen(
                    self._bft_msg_seen,
                    self._bft_network_dedupe_key("vote", vote_json),
                    ttl_ms=self._bft_msg_seen_ttl_ms,
                    now_ms=_now_ms(),
                    max_entries=self._bft_msg_seen_max,
                )
                self._relay_submit_message(msg)

            self._send_local_bft_artifact_if_current("vote", vote_json, _send)
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftOutboundBridgeError):
                    raise
                raise BftOutboundBridgeError("vote_broadcast_failed") from e

    def _broadcast_bft_timeout(self, timeout_json: Json, *, exclude_peer_id: str = "") -> None:
        self._sync_bft_branch_generation()
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

            def _send() -> None:
                self.node.broadcast_message(msg, exclude_peer_id=str(exclude_peer_id or ""))
                self._dedupe_seen(
                    self._bft_timeout_seen,
                    self._bft_network_dedupe_key("timeout", timeout_json),
                    ttl_ms=self._bft_timeout_seen_ttl_ms,
                    now_ms=_now_ms(),
                    max_entries=self._bft_timeout_seen_max,
                )
                self._relay_submit_message(msg)

            self._send_local_bft_artifact_if_current("timeout", timeout_json, _send)
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftOutboundBridgeError):
                    raise
                raise BftOutboundBridgeError("timeout_broadcast_failed") from e

    def _on_bft_proposal(self, peer_id: str, msg: BftProposalMsg) -> bool:
        self._sync_bft_branch_generation()
        try:
            if not self._bft_enabled:
                return

            proposal = self._mk_bft_proposal_json(msg)

            now = _now_ms()
            key = self._bft_generic_key({"t": "proposal", "v": proposal})
            if self._seen_contains(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
            ):
                accepted_fn = getattr(self._executor, "bft_artifact_was_accepted", None)
                if not callable(accepted_fn) or bool(accepted_fn("proposal", proposal)):
                    inc_counter("net_bft_proposal_duplicate")
                    return True
                # A destructive checkpoint can land after the generation sync
                # above but before this seen-cache check. A branch-A cache hit
                # is not sufficient authority to suppress branch-B runtime
                # adjudication once the executor no longer admits the artifact.
                self._bft_msg_seen.pop(key, None)
                self._sync_bft_branch_generation()

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
            if not self._bft_runtime_accepted("proposal", proposal, votej):
                inc_counter("net_bft_proposal_executor_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor, "proposal", proposal, "executor_rejected"
                )
                return False
            self._dedupe_seen(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_msg_seen_max,
            )
            if isinstance(votej, dict) and votej:
                vote_key = self._bft_network_dedupe_key("vote", votej)
                if not self._dedupe_seen(
                    self._bft_msg_seen,
                    vote_key,
                    ttl_ms=self._bft_msg_seen_ttl_ms,
                    now_ms=now,
                    max_entries=self._bft_msg_seen_max,
                ):
                    self._broadcast_bft_vote(votej, exclude_peer_id=str(peer_id or ""))
            self._record_net_metric_gauges()
            return True
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftInboundProcessingError):
                    raise
                raise BftInboundProcessingError("proposal_executor_failed") from e
            return

    def _on_bft_vote(self, peer_id: str, msg: BftVoteMsg) -> bool:
        self._sync_bft_branch_generation()
        try:
            if not self._bft_enabled:
                return

            votej = self._mk_bft_vote_json(msg)
            if not isinstance(votej, dict) or not votej:
                return

            now = _now_ms()
            key = self._bft_network_dedupe_key("vote", votej)
            if self._seen_contains(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
            ):
                accepted_fn = getattr(self._executor, "bft_artifact_was_accepted", None)
                if not callable(accepted_fn) or bool(accepted_fn("vote", votej)):
                    inc_counter("net_bft_vote_duplicate")
                    return True
                self._bft_msg_seen.pop(key, None)
                self._sync_bft_branch_generation()

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
            if not self._bft_runtime_accepted("vote", votej, qcj):
                inc_counter("net_bft_vote_executor_rejected")
                _emit_bft_rejection_diagnostic(self._executor, "vote", votej, "executor_rejected")
                return False
            self._dedupe_seen(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_msg_seen_max,
            )
            if isinstance(qcj, dict) and qcj:
                try:
                    apply_fn = getattr(self._executor, "bft_on_qc", None)
                    if callable(apply_fn):
                        apply_fn(qcj)
                except Exception as e:
                    if _is_prod():
                        raise BftInboundProcessingError("vote_local_qc_apply_failed") from e
                qc_key = self._bft_network_dedupe_key("qc", qcj)
                if not self._dedupe_seen(
                    self._bft_msg_seen,
                    qc_key,
                    ttl_ms=self._bft_msg_seen_ttl_ms,
                    now_ms=now,
                    max_entries=self._bft_msg_seen_max,
                ):
                    qmsg = BftQcMsg(header=self._mk_header(mtype=MsgType.BFT_QC), qc=qcj)
                    try:
                        self._send_local_bft_artifact_if_current(
                            "qc",
                            qcj,
                            lambda: self.node.broadcast_message(
                                qmsg,
                                exclude_peer_id=str(peer_id or ""),
                            ),
                        )
                    except Exception as e:
                        if _is_prod():
                            raise BftInboundProcessingError("vote_qc_broadcast_failed") from e
            self._record_net_metric_gauges()
            return True
        except Exception as e:
            if _is_prod():
                if isinstance(e, BftInboundProcessingError):
                    raise
                raise BftInboundProcessingError("vote_executor_failed") from e
            return

    def _on_bft_qc(self, peer_id: str, msg: BftQcMsg) -> bool:
        self._sync_bft_branch_generation()
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
            key = self._bft_network_dedupe_key("qc", qcj)
            if self._seen_contains(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
            ):
                accepted_fn = getattr(self._executor, "bft_artifact_was_accepted", None)
                if not callable(accepted_fn) or bool(accepted_fn("qc", qcj)):
                    inc_counter("net_bft_qc_duplicate")
                    return True
                self._bft_msg_seen.pop(key, None)
                self._sync_bft_branch_generation()

            fn = getattr(self._executor, "bft_on_qc", None)
            if not callable(fn):
                return False
            out = fn(qcj)
            if not self._bft_runtime_accepted("qc", qcj, out):
                inc_counter("net_bft_qc_executor_rejected")
                _emit_bft_rejection_diagnostic(self._executor, "qc", qcj, "executor_rejected")
                return False
            self._dedupe_seen(
                self._bft_msg_seen,
                key,
                ttl_ms=self._bft_msg_seen_ttl_ms,
                now_ms=now,
                max_entries=self._bft_msg_seen_max,
            )
            self._record_net_metric_gauges()
            return True
        except Exception as e:
            if _is_prod():
                raise BftInboundProcessingError("qc_executor_failed") from e
            return

    def _on_bft_timeout(self, peer_id: str, msg: BftTimeoutMsg) -> bool:
        """Ingress handler for BFT timeouts.

        This is intentionally *always-on* when the net loop is running:
          - Timeouts carry liveness information.
          - Exact retries remain eligible until runtime verification accepts them.
          - Only verified/admitted timeouts enter network dedupe and relay.

        The executor remains the authority for cryptographic timeout admission.
        """

        self._sync_bft_branch_generation()
        try:
            now = _now_ms()
            key = self._bft_timeout_key(msg)
            if self._seen_contains(
                self._bft_timeout_seen,
                key,
                ttl_ms=self._bft_timeout_seen_ttl_ms,
                now_ms=now,
            ):
                timeoutj = self._mk_bft_timeout_json(msg)
                timeout_accepted_fn = getattr(self._executor, "bft_timeout_was_accepted", None)
                accepted_fn = getattr(self._executor, "bft_artifact_was_accepted", None)
                if callable(timeout_accepted_fn):
                    still_current = bool(timeout_accepted_fn(timeoutj))
                elif callable(accepted_fn):
                    still_current = bool(accepted_fn("timeout", timeoutj))
                else:
                    still_current = True
                if still_current:
                    inc_counter("net_bft_timeout_duplicate")
                    return True
                self._bft_timeout_seen.pop(key, None)
                self._sync_bft_branch_generation()
            else:
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
            accepted = False
            fn = getattr(self._executor, "bft_on_timeout", None)
            if callable(fn):
                out = fn(timeoutj)
                accepted_fn = getattr(self._executor, "bft_timeout_was_accepted", None)
                if callable(accepted_fn):
                    accepted = bool(accepted_fn(timeoutj))
                else:
                    accepted = self._bft_runtime_accepted("timeout", timeoutj, out)
            if not accepted:
                inc_counter("net_bft_timeout_executor_rejected")
                _emit_bft_rejection_diagnostic(
                    self._executor, "timeout", timeoutj, "executor_rejected"
                )
                return
            duplicate = {"value": False}

            def _postauth_timeout_side_effect() -> None:
                if self._dedupe_seen(
                    self._bft_timeout_seen,
                    key,
                    ttl_ms=self._bft_timeout_seen_ttl_ms,
                    now_ms=now,
                    max_entries=self._bft_timeout_seen_max,
                ):
                    duplicate["value"] = True
                    return
                if self.node is not None:
                    self.node.broadcast_message(msg, exclude_peer_id=str(peer_id or ""))

            try:
                current = self._run_postauth_bft_side_effect_if_current(
                    "timeout",
                    timeoutj,
                    _postauth_timeout_side_effect,
                )
            except Exception as e:
                if _is_prod():
                    raise BftInboundProcessingError("timeout_broadcast_failed") from e
                return False
            if not current:
                inc_counter("net_bft_timeout_postauth_branch_drop")
                return False
            if bool(duplicate["value"]):
                inc_counter("net_bft_timeout_duplicate")
                return True
            self._record_net_metric_gauges()
            return True
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
        if self.node is None:
            raise NetLoopRuntimeError("node_unavailable_for_wire_header")
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

    def _tx_seen_contains(self, tx_id: str, now_ms: int) -> bool:
        self._tx_seen_prune(now_ms)
        return tx_id in self._tx_seen

    def _tx_seen_record(self, tx_id: str, now_ms: int) -> None:
        self._tx_seen_prune(now_ms)
        if tx_id in self._tx_seen:
            self._tx_seen[tx_id] = int(now_ms)
            return
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

    def _tx_seen_has(self, tx_id: str, now_ms: int) -> bool:
        """Back-compat check-and-record helper used by cache-cap tests."""
        if self._tx_seen_contains(tx_id, now_ms):
            return True
        self._tx_seen_record(tx_id, now_ms)
        return False

    def _outbound_tx_gossip_tick(self) -> None:
        if self.node is None:
            return

        self._sync_bft_branch_generation()
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
                local_chain_id = str(
                    getattr(getattr(self.node, "cfg", None), "chain_id", "")
                    or getattr(self._executor, "chain_id", "")
                    or os.environ.get("WEALL_CHAIN_ID", "")
                    or ""
                ).strip()
                tx_id = compute_tx_id(tx, chain_id=local_chain_id or None)
            except Exception:
                tx_id = ""
            if not tx_id:
                continue
            if self._tx_seen_contains(tx_id, now):
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
            try:
                self._relay_submit_message(msg)
            except Exception as e:
                if _is_prod():
                    raise TxGossipBridgeError("tx_gossip_relay_submit_failed") from e
                continue

            # Dedupe authority is earned only after every enabled transport path
            # completes without error. Failed sends must remain retryable.
            self._tx_seen_record(tx_id, now)

    # ----------------------------
    # Outbound BFT gossip
    # ----------------------------

    def _outbound_bft_tick(self) -> None:
        if self.node is None:
            return

        try:
            pending = getattr(self._executor, "bft_pending_outbound_messages", lambda: [])()
        except Exception as exc:
            if _is_prod():
                raise BftOutboundBridgeError("pending_outbound_read_failed") from exc
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

        if _interval_due_or_clock_rollback(
            now_ms=now,
            last_ms=int(self._last_bft_propose_ms),
            interval_ms=int(self._bft_propose_interval_ms),
        ):
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

        if _interval_due_or_clock_rollback(
            now_ms=now,
            last_ms=int(self._last_bft_vote_ms),
            interval_ms=int(self._bft_vote_interval_ms),
        ):
            self._last_bft_vote_ms = int(now)
            try:
                drive_timeouts = getattr(
                    self._executor, "bft_drive_timeouts", lambda *_a, **_k: None
                )
                out = _call_with_optional_now_once(drive_timeouts, now)
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

        if _interval_due_or_clock_rollback(
            now_ms=now,
            last_ms=int(self._last_bft_timeout_ms),
            interval_ms=int(self._bft_timeout_interval_ms),
        ):
            self._last_bft_timeout_ms = int(now)
            try:
                out = getattr(self._executor, "bft_timeout_check", lambda: None)()
                if isinstance(out, dict) and out:
                    self._broadcast_bft_timeout(out)
            except Exception as e:
                if _is_prod():
                    raise BftOutboundBridgeError("timeout_check_failed") from e
