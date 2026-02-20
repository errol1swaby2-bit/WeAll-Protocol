# src/weall/net/gossip.py
"""
WeAll Protocol — Gossip Engine (Tx / Block Propagation)

Purpose:
  - Deterministic, bounded propagation of transactions and blocks
  - Deduplication by stable ids
  - Fanout-based dissemination (no broadcast storms)
  - Transport-agnostic (works with any net.node)

Non-goals (for now):
  - Reputation-weighted routing
  - Inventory bloom filters
  - Anti-eclipse defenses (later layer)

Design:
  - Best-effort delivery
  - Fail-closed on malformed input
  - Optional "session required" hardening

COHERENCE RULE:
  - tx gossip ids MUST be derived from the same canonical tx_id used by runtime
    (executor + mempool). We prefer tx["_tx_id"] when present, and fall back to
    compute_tx_id_from_dict(chain_id, tx) if needed.

Back-compat:
  - Older code imports `Gossip` from this module. The engine class is named
    `GossipEngine`. We provide `Gossip = GossipEngine` alias.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set

from weall.net.messages import BlockProposalMsg, TxEnvelopeMsg
from weall.runtime.tx_id import compute_tx_id_from_dict
from weall.tx.canon import CanonError


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


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
            return f"tx:{v}"

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
    ttl_ms: int = 5 * 60 * 1000        # 5 minutes
    max_seen: int = 100_000            # cap memory usage
    require_session: bool = True


@dataclass(slots=True)
class GossipState:
    """
    Tracks seen gossip items to prevent loops.
    """
    seen: Dict[str, int] = field(default_factory=dict)  # gossip_id -> first_seen_ms

    def remember(self, gid: str, now_ms: int, *, ttl_ms: int, max_seen: int) -> bool:
        """
        Returns True if the item is new (or expired and re-accepted).
        """
        if len(self.seen) > max_seen:
            self.gc(now_ms, ttl_ms=ttl_ms, max_keep=max_seen)

        first = self.seen.get(gid)
        if first is None:
            self.seen[gid] = now_ms
            return True

        if now_ms - first > ttl_ms:
            self.seen[gid] = now_ms
            return True

        return False

    def gc(self, now_ms: int, *, ttl_ms: int, max_keep: int) -> None:
        expired = [k for k, t in self.seen.items() if now_ms - t > ttl_ms]
        for k in expired:
            self.seen.pop(k, None)

        if len(self.seen) <= max_keep:
            return

        items = sorted(self.seen.items(), key=lambda kv: kv[1])  # oldest first
        drop_n = max(0, len(items) - max_keep)
        for i in range(drop_n):
            self.seen.pop(items[i][0], None)


# ---------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------

SessionCheck = Callable[[str], bool]  # peer_id -> established?


class GossipEngine:
    def __init__(self, *, cfg: Optional[GossipConfig] = None) -> None:
        self.cfg = cfg or GossipConfig()
        self.state = GossipState()

    def _select_fanout(self, peers: Iterable[str], *, exclude: Set[str]) -> List[str]:
        pool = [p for p in peers if p and p not in exclude]
        if not pool:
            return []
        k = int(self.cfg.fanout)
        if k <= 0 or k >= len(pool):
            return pool
        random.shuffle(pool)
        return pool[:k]

    # -------------------------
    # Entry points
    # -------------------------

    def on_inbound_tx(
        self,
        *,
        msg: TxEnvelopeMsg,
        from_peer: str,
        peers: Iterable[str],
        send_fn,
        session_is_established: Optional[SessionCheck] = None,
    ) -> None:
        """
        Handle inbound tx; forward if new.

        send_fn(peer_id, msg)
        session_is_established(peer_id) -> bool (optional)
        """
        if self.cfg.require_session:
            if session_is_established is None or not session_is_established(from_peer):
                return

        now = _now_ms()
        gid = tx_gossip_id(msg, chain_id=self.cfg.chain_id)
        if not self.state.remember(gid, now, ttl_ms=self.cfg.ttl_ms, max_seen=self.cfg.max_seen):
            return

        for pid in self._select_fanout(peers, exclude={from_peer}):
            if self.cfg.require_session and session_is_established is not None:
                if not session_is_established(pid):
                    continue
            send_fn(pid, msg)

    def on_inbound_block(
        self,
        *,
        msg: BlockProposalMsg,
        from_peer: str,
        peers: Iterable[str],
        send_fn,
        session_is_established: Optional[SessionCheck] = None,
    ) -> None:
        if self.cfg.require_session:
            if session_is_established is None or not session_is_established(from_peer):
                return

        now = _now_ms()
        gid = block_gossip_id(msg)
        if not self.state.remember(gid, now, ttl_ms=self.cfg.ttl_ms, max_seen=self.cfg.max_seen):
            return

        for pid in self._select_fanout(peers, exclude={from_peer}):
            if self.cfg.require_session and session_is_established is not None:
                if not session_is_established(pid):
                    continue
            send_fn(pid, msg)


# ---------------------------------------------------------------------
# Back-compat alias
# ---------------------------------------------------------------------

# Some modules/tests historically imported "Gossip" from this module.
Gossip = GossipEngine

