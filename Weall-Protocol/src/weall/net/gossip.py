# src/weall/net/gossip.py
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from weall.net.codec import CanonError
from weall.net.messages import BlockProposalMsg, TxEnvelopeMsg
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
    outbox: set[tuple[str, str]]

    def __init__(self, cfg: GossipConfig) -> None:
        self.cfg = cfg
        self.seen = SeenCache(max_seen=cfg.max_seen, ttl_ms=cfg.ttl_ms)
        self.outbox = set()
