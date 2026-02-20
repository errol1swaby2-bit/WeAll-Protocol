from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from weall.crypto.sig import verify_ed25519_signature
from weall.runtime.sqlite_db import _canon_json

Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def normalize_validators(validators: List[str]) -> List[str]:
    """
    Deterministic validator ordering.
    We sort + de-dup so leader selection is stable even if nodes receive the same set in different orders.
    """
    seen: set[str] = set()
    out: List[str] = []
    for x in validators or []:
        s = _as_str(x)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    out.sort()
    return out


def quorum_threshold(n: int) -> int:
    """Return 2f+1 threshold for n validators (f=floor((n-1)/3))."""
    n2 = max(0, int(n))
    if n2 <= 0:
        return 0
    f = (n2 - 1) // 3
    return 2 * f + 1


def leader_for_view(validators: List[str], view: int) -> str:
    vset = normalize_validators(validators)
    if not vset:
        return ""
    v = int(view)
    return str(vset[v % len(vset)])


def bft_message_id(msg: Json) -> str:
    h = hashlib.sha256(_canon_json(msg).encode("utf-8")).hexdigest()
    return f"bft:{h}"


# -----------------------------
# Canonical signing payloads
# -----------------------------

def canonical_vote_message(
    *,
    chain_id: str,
    view: int,
    block_id: str,
    parent_id: str,
    signer: str,
) -> bytes:
    payload = {
        "t": "VOTE",
        "chain_id": str(chain_id),
        "view": int(view),
        "block_id": str(block_id),
        "parent_id": str(parent_id),
        "signer": str(signer),
    }
    return _canon_json(payload).encode("utf-8")


def canonical_timeout_message(
    *,
    chain_id: str,
    view: int,
    high_qc_id: str,
    signer: str,
) -> bytes:
    payload = {
        "t": "TIMEOUT",
        "chain_id": str(chain_id),
        "view": int(view),
        "high_qc_id": str(high_qc_id),
        "signer": str(signer),
    }
    return _canon_json(payload).encode("utf-8")


# -----------------------------
# Data types
# -----------------------------

@dataclass(frozen=True, slots=True)
class BftVote:
    chain_id: str
    view: int
    block_id: str
    parent_id: str
    signer: str
    pubkey: str
    sig: str

    def to_json(self) -> Json:
        return {
            "t": "VOTE",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "block_id": self.block_id,
            "parent_id": self.parent_id,
            "signer": self.signer,
            "pubkey": self.pubkey,
            "sig": self.sig,
        }

    def verify(self) -> bool:
        if not self.chain_id or not self.block_id or not self.signer:
            return False
        if not self.pubkey or not self.sig:
            return False
        msg = canonical_vote_message(
            chain_id=self.chain_id,
            view=int(self.view),
            block_id=self.block_id,
            parent_id=self.parent_id,
            signer=self.signer,
        )
        return verify_ed25519_signature(message=msg, sig=self.sig, pubkey=self.pubkey)


@dataclass(frozen=True, slots=True)
class QuorumCert:
    chain_id: str
    view: int
    block_id: str
    parent_id: str
    votes: Tuple[Json, ...]

    def to_json(self) -> Json:
        return {
            "t": "QC",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "block_id": self.block_id,
            "parent_id": self.parent_id,
            "votes": list(self.votes),
        }


@dataclass(frozen=True, slots=True)
class BftTimeout:
    chain_id: str
    view: int
    high_qc_id: str
    signer: str
    pubkey: str
    sig: str

    def to_json(self) -> Json:
        return {
            "t": "TIMEOUT",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "high_qc_id": self.high_qc_id,
            "signer": self.signer,
            "pubkey": self.pubkey,
            "sig": self.sig,
        }

    def verify(self) -> bool:
        if not self.chain_id or not self.high_qc_id or not self.signer:
            return False
        if not self.pubkey or not self.sig:
            return False
        msg = canonical_timeout_message(
            chain_id=self.chain_id,
            view=int(self.view),
            high_qc_id=self.high_qc_id,
            signer=self.signer,
        )
        return verify_ed25519_signature(message=msg, sig=self.sig, pubkey=self.pubkey)


# -----------------------------
# Parsing / verification helpers
# -----------------------------

def qc_from_json(q: Json) -> Optional[QuorumCert]:
    if not isinstance(q, dict):
        return None
    if _as_str(q.get("t") or "") not in {"QC", "qc"}:
        # allow missing t, but require core fields below
        pass
    chain_id = _as_str(q.get("chain_id") or "")
    view = _as_int(q.get("view"), 0)
    block_id = _as_str(q.get("block_id") or "")
    parent_id = _as_str(q.get("parent_id") or "")
    votes = q.get("votes")
    if not isinstance(votes, list):
        votes = []
    if not chain_id or not block_id:
        return None
    vv: List[Json] = []
    for v in votes:
        if isinstance(v, dict):
            vv.append(v)
    return QuorumCert(chain_id=chain_id, view=int(view), block_id=block_id, parent_id=parent_id, votes=tuple(vv))


def is_descendant(blocks: Dict[str, Any], *, candidate: str, ancestor: str, max_hops: int = 2048) -> bool:
    """
    Return True iff `ancestor` is on candidate's chain (including equality).
    Requires blocks map entries include "prev_block_id".
    """
    c = str(candidate)
    a = str(ancestor)
    if not a:
        return True
    if c == a:
        return True
    hops = 0
    cur = c
    while cur and hops < max_hops:
        rec = blocks.get(cur)
        if not isinstance(rec, dict):
            return False
        prev = _as_str(rec.get("prev_block_id") or "")
        if not prev:
            return False
        if prev == a:
            return True
        cur = prev
        hops += 1
    return False


def verify_qc(
    *,
    qc: QuorumCert,
    validators: List[str],
    vpub: Optional[Dict[str, str]] = None,
    # Back-compat keyword alias used by older tests/callers.
    validator_pubkeys: Optional[Dict[str, str]] = None,
    require_threshold: bool = True,
) -> bool:
    """
    Verify that QC votes are valid and >= threshold.

    validators is the active validator signer list (accounts).
    vpub/validator_pubkeys maps signer->pubkey for signature verification.

    Back-compat notes:
      - Some callers pass `validator_pubkeys=` instead of `vpub=`.
      - Some callers embed "compact" vote dicts without a "t" field and without
        chain/view/block/parent fields. Those are inferred from the QC.
    """
    if not qc.chain_id or not qc.block_id:
        return False

    vset = set(normalize_validators(validators))
    if not vset:
        return False

    pubmap: Dict[str, str] = {}
    if isinstance(vpub, dict):
        for k, v in vpub.items():
            ks = _as_str(k)
            vs = _as_str(v)
            if ks and vs:
                pubmap[ks] = vs
    if isinstance(validator_pubkeys, dict):
        for k, v in validator_pubkeys.items():
            ks = _as_str(k)
            vs = _as_str(v)
            if ks and vs:
                pubmap[ks] = vs

    seen: set[str] = set()
    good = 0

    for vj in qc.votes:
        if not isinstance(vj, dict):
            continue

        # Accept both full vote envelopes and compact votes used in some tests.
        # Full envelope usually has t="VOTE". Compact has at least signer+sig.
        if _as_str(vj.get("t") or "") not in {"", "VOTE"}:
            continue
        if "signer" not in vj or "sig" not in vj:
            continue

        signer = _as_str(vj.get("signer") or "")
        if not signer or signer in seen:
            continue
        if signer not in vset:
            continue

        pubkey = _as_str(vj.get("pubkey") or "") or _as_str(pubmap.get(signer) or "")
        sig = _as_str(vj.get("sig") or "")
        if not pubkey or not sig:
            continue

        vote = BftVote(
            chain_id=_as_str(vj.get("chain_id") or qc.chain_id),
            view=_as_int(vj.get("view"), qc.view),
            block_id=_as_str(vj.get("block_id") or qc.block_id),
            parent_id=_as_str(vj.get("parent_id") or qc.parent_id),
            signer=signer,
            pubkey=pubkey,
            sig=sig,
        )

        # vote must match qc fields exactly
        if vote.chain_id != qc.chain_id:
            continue
        if int(vote.view) != int(qc.view):
            continue
        if vote.block_id != qc.block_id or vote.parent_id != qc.parent_id:
            continue
        if not vote.verify():
            continue

        seen.add(signer)
        good += 1

    if not require_threshold:
        return good > 0

    th = quorum_threshold(len(vset))
    return good >= th


# -----------------------------
# HotStuff BFT state machine
# -----------------------------

class HotStuffBFT:
    def __init__(self, *, chain_id: str) -> None:
        self.chain_id = str(chain_id)

        self.view: int = 0
        self.high_qc: Optional[QuorumCert] = None
        self.locked_qc: Optional[QuorumCert] = None

        self.finalized_block_id: str = ""
        self.finalized_view: int = 0

        # Local vote safety (prevents equivocation by this node).
        # Persisted so restarts cannot accidentally double-vote.
        self.last_voted_view: int = -1
        self.last_voted_block_id: str = ""

        # vote cache: (view, block_id) -> signer -> vote_json
        self._votes: Dict[Tuple[int, str], Dict[str, Json]] = {}
        # timeout cache: view -> signer -> timeout_json
        self._timeouts: Dict[int, Dict[str, Json]] = {}

        self.last_progress_ms: int = _now_ms()

    # ---- persistence ----

    def load_from_state(self, state: Json) -> None:
        b = state.get("bft")
        if not isinstance(b, dict):
            return
        self.view = _as_int(b.get("view"), self.view)

        hqc = b.get("high_qc")
        if isinstance(hqc, dict):
            q = qc_from_json(hqc)
            if q is not None:
                self.high_qc = q

        lqc = b.get("locked_qc")
        if isinstance(lqc, dict):
            q = qc_from_json(lqc)
            if q is not None:
                self.locked_qc = q

        self.finalized_block_id = _as_str(b.get("finalized_block_id") or self.finalized_block_id)
        self.finalized_view = _as_int(b.get("finalized_view"), self.finalized_view)
        self.last_voted_view = _as_int(b.get("last_voted_view"), self.last_voted_view)
        self.last_voted_block_id = _as_str(b.get("last_voted_block_id") or self.last_voted_block_id)

    def export_state(self) -> Json:
        out: Json = {
            "view": int(self.view),
            "finalized_block_id": self.finalized_block_id,
            "finalized_view": int(self.finalized_view),
            "last_voted_view": int(self.last_voted_view),
            "last_voted_block_id": self.last_voted_block_id,
        }
        if self.high_qc is not None:
            out["high_qc"] = self.high_qc.to_json()
        if self.locked_qc is not None:
            out["locked_qc"] = self.locked_qc.to_json()
        return out

    # ---- core rules ----

    def bump_view(self, new_view: int) -> None:
        v = int(new_view)
        if v > self.view:
            self.view = v
            self.last_progress_ms = _now_ms()

    def can_vote_for(self, *, blocks: Dict[str, Any], block_id: str) -> bool:
        """
        Safety: may vote for a block if it extends the locked QC block.
        If no lock, always safe.
        """
        bid = str(block_id)
        if not bid:
            return False
        if self.locked_qc is None or not self.locked_qc.block_id:
            return True
        return is_descendant(blocks, candidate=bid, ancestor=self.locked_qc.block_id)

    def record_local_vote(self, *, view: int, block_id: str) -> bool:
        """Record a local vote if safe.

        Safety rules:
          - monotonic view voting (cannot vote below last_voted_view)
          - no equivocation within the same view (same view must use same block_id)

        Returns True if vote may proceed and was recorded.
        """
        v = int(view)
        bid = str(block_id).strip()
        if not bid:
            return False

        # Refuse to vote in the past.
        if v < int(self.last_voted_view):
            return False

        # Same-view equivocation guard.
        if v == int(self.last_voted_view) and self.last_voted_block_id and bid != self.last_voted_block_id:
            return False

        self.last_voted_view = v
        self.last_voted_block_id = bid
        return True

    def observe_qc(self, *, blocks: Dict[str, Any], qc: QuorumCert) -> Optional[str]:
        """
        Observe a QC; update highQC/lockedQC, and finalize if we have a 3-chain:
          QC(view=v, block=b3) where parent=b2, grandparent=b1 => finalize b1.
        Returns finalized block_id if newly finalized.
        """
        if qc.chain_id != self.chain_id:
            return None

        # bump view on observed qc
        self.bump_view(int(qc.view) + 1)

        # HighQC always tracks the highest-view QC observed.
        if self.high_qc is None or qc.view > self.high_qc.view:
            self.high_qc = qc

        # LockedQC: update only when it maintains the locked-descendant safety rule.
        # This prevents a remote peer from forcing us to "unlock" onto a conflicting branch.
        if self.locked_qc is None or not self.locked_qc.block_id:
            self.locked_qc = qc
        else:
            # Only move the lock forward if the new QC extends our current lock.
            if is_descendant(blocks, candidate=str(qc.block_id), ancestor=str(self.locked_qc.block_id)):
                if qc.view > self.locked_qc.view:
                    self.locked_qc = qc

        # 3-chain finalize rule: qc on b3 -> finalize b1 (grandparent)
        b3 = qc.block_id
        rec3 = blocks.get(b3)
        if not isinstance(rec3, dict):
            return None
        b2 = _as_str(rec3.get("prev_block_id") or "")
        if not b2:
            return None
        rec2 = blocks.get(b2)
        if not isinstance(rec2, dict):
            return None
        b1 = _as_str(rec2.get("prev_block_id") or "")
        if not b1:
            return None

        # finalize b1 if higher view than current finalized
        if int(qc.view) >= int(self.finalized_view) and b1 and b1 != self.finalized_block_id:
            self.finalized_block_id = b1
            self.finalized_view = int(qc.view)
            self.last_progress_ms = _now_ms()
            return b1
        return None

    # ---- vote aggregation ----

    def accept_vote(self, *, vote_json: Json, validators: List[str], vpub: Dict[str, str]) -> Optional[QuorumCert]:
        """
        Accept a VOTE, cache it, and if threshold reached for (view, block_id) return a QC.
        """
        if not isinstance(vote_json, dict):
            return None
        if _as_str(vote_json.get("t") or "") != "VOTE":
            return None

        vote = BftVote(
            chain_id=_as_str(vote_json.get("chain_id") or self.chain_id),
            view=_as_int(vote_json.get("view"), 0),
            block_id=_as_str(vote_json.get("block_id") or ""),
            parent_id=_as_str(vote_json.get("parent_id") or ""),
            signer=_as_str(vote_json.get("signer") or ""),
            pubkey=_as_str(vote_json.get("pubkey") or ""),
            sig=_as_str(vote_json.get("sig") or ""),
        )
        if vote.chain_id != self.chain_id:
            return None
        if not vote.block_id or not vote.signer:
            return None

        # Verify signature and membership.
        vset = set(normalize_validators(validators))
        if vote.signer not in vset:
            return None
        pubkey = vote.pubkey or _as_str(vpub.get(vote.signer) or "")
        if not pubkey:
            return None
        vote2 = BftVote(
            chain_id=vote.chain_id,
            view=int(vote.view),
            block_id=vote.block_id,
            parent_id=vote.parent_id,
            signer=vote.signer,
            pubkey=pubkey,
            sig=vote.sig,
        )
        if not vote2.verify():
            return None

        key = (int(vote2.view), vote2.block_id)
        bucket = self._votes.get(key)
        if bucket is None:
            bucket = {}
            self._votes[key] = bucket
        # cache only first per signer (prevents duplicates)
        if vote2.signer not in bucket:
            bucket[vote2.signer] = vote2.to_json()

        th = quorum_threshold(len(vset))
        if len(bucket) >= th:
            qc = QuorumCert(
                chain_id=self.chain_id,
                view=int(vote2.view),
                block_id=vote2.block_id,
                parent_id=vote2.parent_id,
                votes=tuple(bucket.values()),
            )
            # QC should verify as a whole.
            if verify_qc(qc=qc, validators=validators, vpub=vpub, require_threshold=True):
                self.last_progress_ms = _now_ms()
                return qc
        return None

    # ---- timeout aggregation ----

    def accept_timeout(self, *, timeout_json: Json, validators: List[str], vpub: Dict[str, str]) -> Optional[int]:
        """
        Accept TIMEOUT; if threshold reached for view, return new_view to advance to.
        """
        if not isinstance(timeout_json, dict):
            return None
        if _as_str(timeout_json.get("t") or "") != "TIMEOUT":
            return None

        tmo = BftTimeout(
            chain_id=_as_str(timeout_json.get("chain_id") or self.chain_id),
            view=_as_int(timeout_json.get("view"), 0),
            high_qc_id=_as_str(timeout_json.get("high_qc_id") or ""),
            signer=_as_str(timeout_json.get("signer") or ""),
            pubkey=_as_str(timeout_json.get("pubkey") or ""),
            sig=_as_str(timeout_json.get("sig") or ""),
        )
        if tmo.chain_id != self.chain_id:
            return None

        vset = set(normalize_validators(validators))
        if tmo.signer not in vset:
            return None
        pubkey = tmo.pubkey or _as_str(vpub.get(tmo.signer) or "")
        if not pubkey:
            return None

        tmo2 = BftTimeout(
            chain_id=tmo.chain_id,
            view=int(tmo.view),
            high_qc_id=tmo.high_qc_id,
            signer=tmo.signer,
            pubkey=pubkey,
            sig=tmo.sig,
        )
        if not tmo2.verify():
            return None

        v = int(tmo2.view)
        bucket = self._timeouts.get(v)
        if bucket is None:
            bucket = {}
            self._timeouts[v] = bucket
        if tmo2.signer not in bucket:
            bucket[tmo2.signer] = tmo2.to_json()

        th = quorum_threshold(len(vset))
        if len(bucket) >= th:
            # advance view
            new_view = v + 1
            self.bump_view(new_view)
            self.last_progress_ms = _now_ms()
            return new_view
        return None
