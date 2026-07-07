# src/weall/net/gossip.py
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

from weall.crypto.sig import sign_signature_for_profile, verify_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1, default_signature_profile_for_mode
from weall.net.messages import BlockProposalMsg, TxEnvelopeMsg
from weall.tx.canon import CanonError
from weall.runtime.tx_id import compute_tx_id_from_dict

JsonObject = dict[str, object]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw is None:
        return str(default)
    s = str(raw)
    return s if s else str(default)


def _env_int(name: str, default: int) -> int:
    raw = _env_str(name, "").strip()
    if not raw:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    raw = _env_str(name, "").strip().lower()
    if not raw:
        return bool(default)
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _mode() -> str:
    return _env_str("WEALL_MODE", "dev").strip().lower() or "dev"


# ---------------------------------------------------------------------
# Gossip IDs
# ---------------------------------------------------------------------


def tx_gossip_id(msg: TxEnvelopeMsg, *, chain_id: str) -> str:
    """
    Stable identifier for tx gossip.

    Policy:
      - Prefer tx["_tx_id"] (guaranteed on outbound; normalized on inbound by codec)
      - Otherwise accept tx["tx_id"] / tx["id"] as candidates
      - Otherwise compute canonical tx id from the tx dict using runtime/tx_id.py
    """
    tx = msg.tx
    if not isinstance(tx, dict):
        raise CanonError("TxEnvelopeMsg.tx must be a dict")

    for key in ("_tx_id", "tx_id", "id"):
        v = tx.get(key)
        if isinstance(v, str) and v:
            sv = str(v)
            return sv if sv.startswith("tx:") else f"tx:{sv}"

    computed = compute_tx_id_from_dict(str(chain_id), tx)
    return f"tx:{computed}"


def block_gossip_id(blk: BlockProposalMsg) -> str:
    """
    Stable identifier for block gossip.
    """
    bh = getattr(blk, "block_hash", None)
    if isinstance(bh, str) and bh:
        return f"blk:{bh}"
    return f"blk:{blk.height}:{blk.prev_block_hash}"


# ---------------------------------------------------------------------
# Config + state
# ---------------------------------------------------------------------


@dataclass(slots=True)
class GossipConfig:
    """
    Tunables for gossip behavior.

    chain_id:
      - Used to compute canonical tx_id when inbound tx dict does not include one.

    require_session:
      - If True, inbound messages are only accepted from peers for whom
        session_is_established(peer_id) returns True.
      - This is a lightweight hardening against pre-handshake spam.
    """

    chain_id: str = "weall-devnet"
    fanout: int = 4
    max_seen: int = 50_000
    ttl_ms: int = 10 * 60 * 1000
    require_session: bool = False


@dataclass
class SeenCache:
    """A bounded, TTL-based seen cache for gossip ids."""

    max_seen: int
    ttl_ms: int
    seen: dict[str, int]

    def __init__(self, *, max_seen: int, ttl_ms: int) -> None:
        self.max_seen = int(max_seen)
        self.ttl_ms = int(ttl_ms)
        self.seen = {}

    def _prune(self, *, now_ms: int) -> None:
        if self.ttl_ms > 0:
            cutoff = int(now_ms) - int(self.ttl_ms)
            dead = [k for k, ts in self.seen.items() if int(ts) <= cutoff]
            for k in dead:
                self.seen.pop(k, None)

        # hard cap
        if self.max_seen > 0 and len(self.seen) > self.max_seen:
            # drop oldest entries
            items = sorted(self.seen.items(), key=lambda kv: int(kv[1]))
            for k, _ts in items[: max(0, len(items) - self.max_seen)]:
                self.seen.pop(k, None)

    def mark(self, key: str, *, now_ms: int | None = None) -> None:
        now = int(now_ms) if now_ms is not None else _now_ms()
        self._prune(now_ms=now)
        self.seen[str(key)] = int(now)

    def has(self, key: str, *, now_ms: int | None = None) -> bool:
        now = int(now_ms) if now_ms is not None else _now_ms()
        self._prune(now_ms=now)
        return str(key) in self.seen


@dataclass
class GossipState:
    cfg: GossipConfig
    seen: SeenCache
    tx_queue: set[tuple[str, str]]

    def __init__(self, cfg: GossipConfig) -> None:
        self.cfg = cfg
        self.seen = SeenCache(max_seen=cfg.max_seen, ttl_ms=cfg.ttl_ms)
        self.tx_queue = set()


# ---------------------------------------------------------------------
# Bitcoin-style peer address gossip
# ---------------------------------------------------------------------

_ADDR_GOSSIP_DOMAIN = "WEALL_PEER_ADDR_V1"
_SUPPORTED_PEER_URI_PREFIXES = ("tcp://", "tls://")


@dataclass(frozen=True, slots=True)
class PeerAddrGossipConfig:
    """Compatibility and safety settings for peer-address relay.

    Address gossip is deliberately node-local networking metadata. It helps
    nodes discover one another, but it does not create consensus authority and
    must never affect deterministic block validity.
    """

    chain_id: str
    schema_version: str
    tx_index_hash: str
    max_addrs_per_message: int = 64
    max_record_ttl_ms: int = 7 * 24 * 60 * 60 * 1000
    allow_unsigned: bool = True


def normalize_peer_uri(uri: Any) -> str:
    return str(uri or "").strip()


def is_supported_peer_uri(uri: Any) -> bool:
    s = normalize_peer_uri(uri)
    return bool(s) and s.startswith(_SUPPORTED_PEER_URI_PREFIXES)


def _canon_addr_signing_payload(record: JsonObject) -> bytes:
    data = {
        "domain": _ADDR_GOSSIP_DOMAIN,
        "uri": str(record.get("uri") or ""),
        "peer_id": str(record.get("peer_id") or ""),
        "chain_id": str(record.get("chain_id") or ""),
        "schema_version": str(record.get("schema_version") or ""),
        "tx_index_hash": str(record.get("tx_index_hash") or ""),
        "valid_from_ms": int(record.get("valid_from_ms") or 0),
        "expires_at_ms": int(record.get("expires_at_ms") or 0),
        "sig_profile": str(record.get("sig_profile") or PQ_MLDSA_V1).strip(),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_peer_addr_record(
    *,
    uri: str,
    peer_id: str,
    chain_id: str,
    schema_version: str,
    tx_index_hash: str,
    now_ms: int | None = None,
    ttl_ms: int | None = None,
    pubkey: str | None = None,
    privkey: str | None = None,
    sig_profile: str | None = None,
) -> JsonObject:
    """Create a relayable peer address record.

    If pubkey+privkey are supplied, the record is signed with an explicit
    signature profile.  Controlled/public testnet mode defaults to pq-mldsa-v1;
    pq-mldsa-v1 is the only accepted gossip signature profile. Unsigned
    records are still useful for discovery but remain untrusted hints until the
    normal PEER_HELLO handshake succeeds.
    """

    clean_uri = normalize_peer_uri(uri)
    if not is_supported_peer_uri(clean_uri):
        raise ValueError("unsupported_peer_uri")
    now = int(now_ms if now_ms is not None else _now_ms())
    ttl = int(ttl_ms if ttl_ms is not None else 7 * 24 * 60 * 60 * 1000)
    if ttl <= 0:
        ttl = 7 * 24 * 60 * 60 * 1000
    rec: JsonObject = {
        "uri": clean_uri,
        "peer_id": str(peer_id or "").strip(),
        "chain_id": str(chain_id or "").strip(),
        "schema_version": str(schema_version or "").strip(),
        "tx_index_hash": str(tx_index_hash or "").strip(),
        "valid_from_ms": now,
        "expires_at_ms": now + ttl,
        "last_seen_ms": now,
    }
    pk = str(pubkey or "").strip()
    sk = str(privkey or "").strip()
    if pk and sk:
        profile = str(sig_profile or default_signature_profile_for_mode()).strip() or PQ_MLDSA_V1
        rec["pubkey"] = pk
        rec["sig_profile"] = profile
        rec["sig_alg"] = "ML-DSA"
        rec["sig"] = sign_signature_for_profile(
            sig_profile=profile,
            message=_canon_addr_signing_payload(rec),
            privkey=sk,
            encoding="hex",
        )
    return rec


def verify_peer_addr_record(record: Any, *, cfg: PeerAddrGossipConfig, now_ms: int | None = None) -> bool:
    """Return True only for address records that are safe to persist/relay.

    This function enforces local networking compatibility. It does not grant
    authority; any later connection still has to pass the hardened handshake.
    """

    if not isinstance(record, dict):
        return False
    uri = normalize_peer_uri(record.get("uri"))
    if not is_supported_peer_uri(uri):
        return False
    if str(record.get("chain_id") or "") != str(cfg.chain_id):
        return False
    if str(record.get("schema_version") or "") != str(cfg.schema_version):
        return False
    if str(record.get("tx_index_hash") or "") != str(cfg.tx_index_hash):
        return False
    now = int(now_ms if now_ms is not None else _now_ms())
    try:
        expires_at_ms = int(record.get("expires_at_ms") or 0)
        valid_from_ms = int(record.get("valid_from_ms") or 0)
    except Exception:
        return False
    if expires_at_ms and expires_at_ms <= now:
        return False
    if valid_from_ms and valid_from_ms > now + 5 * 60 * 1000:
        return False
    if expires_at_ms and valid_from_ms and int(cfg.max_record_ttl_ms) > 0:
        if expires_at_ms - valid_from_ms > int(cfg.max_record_ttl_ms):
            return False

    sig = str(record.get("sig") or "").strip()
    pubkey = str(record.get("pubkey") or "").strip()
    if not sig and not pubkey:
        return bool(cfg.allow_unsigned)
    if not sig or not pubkey:
        return False
    profile = str(record.get("sig_profile") or "").strip()
    if not profile:
        profile = PQ_MLDSA_V1
    if not profile:
        return False
    try:
        return bool(
            verify_signature_for_profile(
                sig_profile=profile,
                message=_canon_addr_signing_payload({**record, "sig_profile": profile}),
                sig=sig,
                pubkey=pubkey,
            )
        )
    except Exception:
        return False


def filter_peer_addr_records(
    records: Any,
    *,
    cfg: PeerAddrGossipConfig,
    now_ms: int | None = None,
) -> tuple[JsonObject, ...]:
    if not isinstance(records, (list, tuple)):
        return ()
    out: list[JsonObject] = []
    seen: set[str] = set()
    limit = max(0, int(cfg.max_addrs_per_message))
    if limit <= 0:
        return ()
    for raw in records:
        if not isinstance(raw, dict):
            continue
        if not verify_peer_addr_record(raw, cfg=cfg, now_ms=now_ms):
            continue
        uri = normalize_peer_uri(raw.get("uri"))
        if uri in seen:
            continue
        seen.add(uri)
        out.append(dict(raw))
        if len(out) >= limit:
            break
    return tuple(out)
