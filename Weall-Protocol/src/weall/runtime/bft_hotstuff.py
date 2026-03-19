from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import Any

from weall.crypto.sig import verify_ed25519_signature
from weall.runtime.sqlite_db import _canon_json

Json = dict[str, Any]

# Canonical production consensus contract.
#
# Batch 1 freezes these semantics so the implementation and operator-facing
# surfaces describe the same protocol rules. This codebase does not implement
# random proposer selection or a 60% quorum rule.
CONSENSUS_ALGORITHM = "hotstuff_bft"
LEADER_SELECTION_RULE = "deterministic_round_robin_sorted_validator_set"
QUORUM_RULE = "ceil_2n_over_3"
FINALITY_RULE = "hotstuff_three_chain"
VALIDATOR_NORMALIZATION_RULE = "sort_and_dedup"

CONSENSUS_PHASE_SOLO_BOOTSTRAP = "solo_bootstrap"
CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP = "multi_validator_bootstrap"
CONSENSUS_PHASE_BFT_ACTIVE = "bft_active"
CONSENSUS_PHASES = {
    CONSENSUS_PHASE_SOLO_BOOTSTRAP,
    CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP,
    CONSENSUS_PHASE_BFT_ACTIVE,
}
BFT_MIN_VALIDATORS = 4


def normalize_consensus_phase(phase: Any, *, validator_count: int = 0) -> str:
    raw = _as_str(phase).lower()
    if raw in CONSENSUS_PHASES:
        return raw
    count = max(0, int(validator_count))
    if count <= 1:
        return CONSENSUS_PHASE_SOLO_BOOTSTRAP
    return CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP


def fault_tolerance_for_validator_count(n: int) -> int:
    n2 = max(0, int(n))
    if n2 < BFT_MIN_VALIDATORS:
        return 0
    return max((n2 - 1) // 3, 0)


def consensus_security_summary(validators: list[str] | None = None, *, phase: Any = "") -> Json:
    normalized = normalize_validators(list(validators or []))
    count = int(len(normalized))
    normalized_phase = normalize_consensus_phase(phase, validator_count=count)
    quorum = quorum_threshold(count) if count > 0 else 0
    fault_tolerance = fault_tolerance_for_validator_count(count)
    bft_ready = count >= BFT_MIN_VALIDATORS
    return {
        "phase": normalized_phase,
        "validator_count": count,
        "quorum_threshold": quorum,
        "bft_min_validators": int(BFT_MIN_VALIDATORS),
        "bft_ready": bool(bft_ready),
        "fault_tolerance": int(fault_tolerance),
        "safety_model": "single_operator_bootstrap"
        if normalized_phase == CONSENSUS_PHASE_SOLO_BOOTSTRAP
        else (
            "coordinated_multivalidator_bootstrap"
            if normalized_phase == CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP
            else "hotstuff_bft"
        ),
        "public_bft_active": bool(normalized_phase == CONSENSUS_PHASE_BFT_ACTIVE),
        "degraded_reason": "validator_count_below_bft_minimum"
        if count < BFT_MIN_VALIDATORS
        else "",
    }


def consensus_contract_summary(validators: list[str] | None = None) -> Json:
    normalized = normalize_validators(list(validators or []))
    return {
        "algorithm": CONSENSUS_ALGORITHM,
        "validator_normalization": VALIDATOR_NORMALIZATION_RULE,
        "leader_selection": LEADER_SELECTION_RULE,
        "leader_formula": "normalize(validators)[view % n]",
        "quorum_rule": QUORUM_RULE,
        "quorum_formula": "ceil(2n/3)",
        "finality_rule": FINALITY_RULE,
        "normalized_validator_set": list(normalized),
        "normalized_validator_count": int(len(normalized)),
        "validator_set_hash": validator_set_hash(normalized),
    }


def _now_ms() -> int:
    return int(time.time() * 1000)


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def normalize_validators(validators: list[str]) -> list[str]:
    """
    Deterministic validator ordering.
    We sort + de-dup so leader selection is stable even if nodes receive the same set in different orders.
    """
    seen: set[str] = set()
    out: list[str] = []
    for x in validators or []:
        s = _as_str(x)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    out.sort()
    return out


def quorum_threshold(n: int) -> int:
    """Return the Byzantine quorum threshold for ``n`` validators.

    We require a supermajority of at least ceil(2n/3), which matches the
    ``2f + 1`` HotStuff quorum when ``n = 3f + 1`` and remains conservative for
    intermediate validator-set sizes.
    """
    n2 = max(0, int(n))
    if n2 <= 0:
        return 0
    return int(math.ceil((2 * n2) / 3.0))


def leader_for_view(validators: list[str], view: int) -> str:
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
    block_hash: str,
    parent_id: str,
    signer: str,
    validator_epoch: int = 0,
    validator_set_hash: str = "",
) -> bytes:
    payload = {
        "t": "VOTE",
        "chain_id": str(chain_id),
        "view": int(view),
        "block_id": str(block_id),
        "block_hash": str(block_hash),
        "parent_id": str(parent_id),
        "signer": str(signer),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
    }
    return _canon_json(payload).encode("utf-8")


def canonical_timeout_message(
    *,
    chain_id: str,
    view: int,
    high_qc_id: str,
    signer: str,
    validator_epoch: int = 0,
    validator_set_hash: str = "",
) -> bytes:
    payload = {
        "t": "TIMEOUT",
        "chain_id": str(chain_id),
        "view": int(view),
        "high_qc_id": str(high_qc_id),
        "signer": str(signer),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
    }
    return _canon_json(payload).encode("utf-8")


def canonical_proposal_message(
    *,
    chain_id: str,
    view: int,
    block_id: str,
    block_hash: str,
    parent_id: str,
    proposer: str,
    validator_epoch: int = 0,
    validator_set_hash: str = "",
    justify_qc_id: str = "",
) -> bytes:
    payload = {
        "t": "PROPOSAL",
        "chain_id": str(chain_id),
        "view": int(view),
        "block_id": str(block_id),
        "block_hash": str(block_hash),
        "parent_id": str(parent_id),
        "proposer": str(proposer),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
        "justify_qc_id": str(justify_qc_id),
    }
    return _canon_json(payload).encode("utf-8")


def validator_set_hash(validators: list[str]) -> str:
    return hashlib.sha256(_canon_json(normalize_validators(validators)).encode("utf-8")).hexdigest()


# -----------------------------
# Data types
# -----------------------------


@dataclass(frozen=True, slots=True)
class BftVote:
    chain_id: str
    view: int
    block_id: str
    block_hash: str
    parent_id: str
    signer: str
    pubkey: str
    sig: str
    validator_epoch: int = 0
    validator_set_hash: str = ""

    def to_json(self) -> Json:
        return {
            "t": "VOTE",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "block_id": self.block_id,
            "block_hash": self.block_hash,
            "parent_id": self.parent_id,
            "signer": self.signer,
            "pubkey": self.pubkey,
            "sig": self.sig,
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
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
            block_hash=self.block_hash,
            parent_id=self.parent_id,
            signer=self.signer,
            validator_epoch=int(self.validator_epoch),
            validator_set_hash=self.validator_set_hash,
        )
        return verify_ed25519_signature(message=msg, sig=self.sig, pubkey=self.pubkey)


@dataclass(frozen=True, slots=True)
class QuorumCert:
    chain_id: str
    view: int
    block_id: str
    block_hash: str
    parent_id: str
    votes: tuple[Json, ...]
    validator_epoch: int = 0
    validator_set_hash: str = ""

    def to_json(self) -> Json:
        return {
            "t": "QC",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "block_id": self.block_id,
            "block_hash": self.block_hash,
            "parent_id": self.parent_id,
            "votes": list(self.votes),
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
        }


@dataclass(frozen=True, slots=True)
class TimeoutCertificate:
    chain_id: str
    view: int
    high_qc_id: str
    signer_count: int
    signers: tuple[str, ...]
    validator_epoch: int = 0
    validator_set_hash: str = ""

    def to_json(self) -> Json:
        return {
            "t": "TC",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "high_qc_id": self.high_qc_id,
            "signer_count": int(self.signer_count),
            "signers": list(self.signers),
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
        }


@dataclass(frozen=True, slots=True)
class BftTimeout:
    chain_id: str
    view: int
    high_qc_id: str
    signer: str
    pubkey: str
    sig: str
    validator_epoch: int = 0
    validator_set_hash: str = ""

    def to_json(self) -> Json:
        return {
            "t": "TIMEOUT",
            "chain_id": self.chain_id,
            "view": int(self.view),
            "high_qc_id": self.high_qc_id,
            "signer": self.signer,
            "pubkey": self.pubkey,
            "sig": self.sig,
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
        }

    def verify(self) -> bool:
        if not self.chain_id or not self.signer:
            return False
        if not self.pubkey or not self.sig:
            return False
        msg = canonical_timeout_message(
            chain_id=self.chain_id,
            view=int(self.view),
            high_qc_id=self.high_qc_id,
            signer=self.signer,
            validator_epoch=int(self.validator_epoch),
            validator_set_hash=self.validator_set_hash,
        )
        return verify_ed25519_signature(message=msg, sig=self.sig, pubkey=self.pubkey)


# -----------------------------
# Parsing / verification helpers
# -----------------------------


def qc_from_json(q: Json) -> QuorumCert | None:
    if not isinstance(q, dict):
        return None
    if _as_str(q.get("t") or "") not in {"QC", "qc"}:
        # allow missing t, but require core fields below
        pass
    chain_id = _as_str(q.get("chain_id") or "")
    view = _as_int(q.get("view"), 0)
    block_id = _as_str(q.get("block_id") or "")
    block_hash = _as_str(q.get("block_hash") or "")
    parent_id = _as_str(q.get("parent_id") or "")
    votes = q.get("votes")
    validator_epoch = _as_int(q.get("validator_epoch"), 0)
    validator_set_hash_s = _as_str(q.get("validator_set_hash") or "")
    if not isinstance(votes, list):
        votes = []
    if not chain_id or not block_id:
        return None
    vv: list[Json] = []
    for v in votes:
        if isinstance(v, dict):
            vv.append(v)
    return QuorumCert(
        chain_id=chain_id,
        view=int(view),
        block_id=block_id,
        block_hash=block_hash,
        parent_id=parent_id,
        votes=tuple(vv),
        validator_epoch=int(validator_epoch),
        validator_set_hash=validator_set_hash_s,
    )


def is_descendant(
    blocks: dict[str, Any], *, candidate: str, ancestor: str, max_hops: int = 2048
) -> bool:
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
    validators: list[str],
    vpub: dict[str, str] | None = None,
    validator_pubkeys: dict[str, str] | None = None,
    require_threshold: bool = True,
) -> bool:
    """
    Verify that QC votes are valid and >= threshold.

    validators is the active validator signer list (accounts).
    vpub/validator_pubkeys maps signer->pubkey for signature verification.

    Compatibility notes:
      - Some callers pass `validator_pubkeys=` instead of `vpub=`.
      - Some callers embed compact vote dicts and rely on the QC envelope for
        chain/view/block/parent metadata. We still infer those fields, but every
        vote must verify against the fully bound canonical message that includes
        block_hash, validator_epoch, and validator_set_hash.
    """
    if not qc.chain_id or not qc.block_id or not qc.block_hash:
        return False

    vset = set(normalize_validators(validators))
    if not vset:
        return False

    pubmap: dict[str, str] = {}
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

        vote_chain_id = _as_str(vj.get("chain_id") or qc.chain_id)
        vote_view = _as_int(vj.get("view"), qc.view)
        vote_block_id = _as_str(vj.get("block_id") or qc.block_id)
        vote_block_hash = _as_str(vj.get("block_hash") or qc.block_hash)
        vote_parent_id = _as_str(vj.get("parent_id") or qc.parent_id)
        has_set_hash_field = "validator_set_hash" in vj
        vote_epoch = _as_int(vj.get("validator_epoch"), qc.validator_epoch)
        if has_set_hash_field:
            vote_set_hash = _as_str(vj.get("validator_set_hash"))
        else:
            vote_set_hash = _as_str(qc.validator_set_hash)

        vote = BftVote(
            chain_id=vote_chain_id,
            view=vote_view,
            block_id=vote_block_id,
            block_hash=vote_block_hash,
            parent_id=vote_parent_id,
            signer=signer,
            pubkey=pubkey,
            sig=sig,
            validator_epoch=vote_epoch,
            validator_set_hash=vote_set_hash,
        )

        strict_meta_match = True
        if vote.chain_id != qc.chain_id:
            strict_meta_match = False
        if int(vote.view) != int(qc.view):
            strict_meta_match = False
        if (
            vote.block_id != qc.block_id
            or vote.block_hash != qc.block_hash
            or vote.parent_id != qc.parent_id
        ):
            strict_meta_match = False

        if int(vote.validator_epoch) != int(qc.validator_epoch):
            strict_meta_match = False
        if str(vote.validator_set_hash or "") != str(qc.validator_set_hash or ""):
            strict_meta_match = False
        if not strict_meta_match:
            continue
        if not vote.verify():
            continue

        seen.add(signer)
        good += 1

    if not require_threshold:
        return good > 0

    th = quorum_threshold(len(vset))
    return good >= th


def verify_proposal_json(
    *,
    proposal: Json,
    validators: list[str],
    vpub: dict[str, str] | None = None,
    expected_leader: str = "",
) -> bool:
    if not isinstance(proposal, dict):
        return False
    proposer = _as_str(proposal.get("proposer") or "")
    if not proposer:
        return False
    if expected_leader and proposer != expected_leader:
        return False
    vset = set(normalize_validators(validators))
    if proposer not in vset:
        return False
    pubmap = dict(vpub or {})
    pubkey = _as_str(proposal.get("proposer_pubkey") or pubmap.get(proposer) or "")
    sig = _as_str(proposal.get("proposer_sig") or "")
    if not pubkey or not sig or not _as_str(proposal.get("block_hash") or ""):
        return False
    msg = canonical_proposal_message(
        chain_id=_as_str(proposal.get("chain_id") or ""),
        view=_as_int(proposal.get("view"), 0),
        block_id=_as_str(proposal.get("block_id") or ""),
        block_hash=_as_str(proposal.get("block_hash") or ""),
        parent_id=_as_str(proposal.get("prev_block_id") or ""),
        proposer=proposer,
        validator_epoch=_as_int(proposal.get("validator_epoch"), 0),
        validator_set_hash=_as_str(proposal.get("validator_set_hash") or ""),
        justify_qc_id=_as_str(_as_dict(proposal.get("justify_qc") or {}).get("block_id") or ""),
    )
    return verify_ed25519_signature(message=msg, sig=sig, pubkey=pubkey)


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


# -----------------------------
# HotStuff BFT state machine
# -----------------------------


class HotStuffBFT:
    def __init__(self, *, chain_id: str) -> None:
        self.chain_id = str(chain_id)

        self.view: int = 0
        self.high_qc: QuorumCert | None = None
        self.locked_qc: QuorumCert | None = None

        self.finalized_block_id: str = ""
        self.finalized_view: int = 0

        # Local vote safety (prevents equivocation by this node).
        # Persisted so restarts cannot accidentally double-vote.
        self.last_voted_view: int = -1
        self.last_voted_block_id: str = ""

        # Local proposal safety (prevents same-view proposal equivocation by this
        # node across crashes/restarts).
        self.last_proposed_view: int = -1
        self.last_proposed_block_id: str = ""

        # vote cache: (view, block_id, block_hash) -> signer -> vote_json
        self._votes: dict[tuple[int, str, str], dict[str, Json]] = {}
        # timeout cache: view -> signer -> timeout_json
        self._timeouts: dict[int, dict[str, Json]] = {}

        # Restart-safe liveness caches. These are node-local hints only and are
        # persisted under the non-consensus ``bft`` subtree so restarts during a
        # partition do not discard partially collected votes/timeouts.
        self.max_persisted_vote_buckets: int = 128
        self.max_persisted_timeout_buckets: int = 64
        self.max_votes_per_bucket: int = 256
        self.max_timeouts_per_bucket: int = 256

        # Highest threshold timeout certificate observed locally. This is a
        # liveness aid only; it never changes block validity by itself. It lets
        # a restarted/new leader recover the highest referenced QC id from a
        # threshold of timeout messages and persist that recovery hint across
        # restarts.
        self.last_timeout_certificate: TimeoutCertificate | None = None

        self.last_progress_ms: int = _now_ms()
        # Adaptive pacemaker state. This is node-local and only affects when we
        # emit timeout messages, never block validity.
        self.timeout_base_ms: int = 10_000
        self.timeout_backoff_exp: int = 0
        self.timeout_backoff_cap: int = 4
        self.last_timeout_view: int = -1

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
        self.last_proposed_view = _as_int(b.get("last_proposed_view"), self.last_proposed_view)
        self.last_proposed_block_id = _as_str(
            b.get("last_proposed_block_id") or self.last_proposed_block_id
        )
        self.timeout_base_ms = max(250, _as_int(b.get("timeout_base_ms"), self.timeout_base_ms))
        self.timeout_backoff_exp = max(
            0, _as_int(b.get("timeout_backoff_exp"), self.timeout_backoff_exp)
        )
        self.timeout_backoff_cap = max(
            0, _as_int(b.get("timeout_backoff_cap"), self.timeout_backoff_cap)
        )
        self.last_timeout_view = _as_int(b.get("last_timeout_view"), self.last_timeout_view)
        self.last_progress_ms = _as_int(b.get("last_progress_ms"), self.last_progress_ms)

        tcj = b.get("last_timeout_certificate")
        if isinstance(tcj, dict):
            signers_any = tcj.get("signers")
            signers: list[str] = []
            if isinstance(signers_any, list):
                for s in signers_any:
                    ss = _as_str(s)
                    if ss:
                        signers.append(ss)
            self.last_timeout_certificate = TimeoutCertificate(
                chain_id=_as_str(tcj.get("chain_id") or self.chain_id),
                view=_as_int(tcj.get("view"), 0),
                high_qc_id=_as_str(tcj.get("high_qc_id") or ""),
                signer_count=max(0, _as_int(tcj.get("signer_count"), len(signers))),
                signers=tuple(signers),
                validator_epoch=_as_int(tcj.get("validator_epoch"), 0),
                validator_set_hash=_as_str(tcj.get("validator_set_hash") or ""),
            )

        votes_any = b.get("pending_votes")
        if isinstance(votes_any, list):
            restored_votes: dict[tuple[int, str, str], dict[str, Json]] = {}
            for item in votes_any:
                if not isinstance(item, dict):
                    continue
                view = _as_int(item.get("view"), -1)
                block_id = _as_str(item.get("block_id") or "")
                block_hash = _as_str(item.get("block_hash") or "")
                votes_list = item.get("votes")
                if view < 0 or not block_id or not block_hash or not isinstance(votes_list, list):
                    continue
                bucket: dict[str, Json] = {}
                for vj in votes_list[: max(1, int(self.max_votes_per_bucket))]:
                    if not isinstance(vj, dict):
                        continue
                    signer = _as_str(vj.get("signer") or "")
                    if signer and signer not in bucket:
                        bucket[signer] = dict(vj)
                if bucket:
                    restored_votes[(int(view), block_id, block_hash)] = bucket
            self._votes = restored_votes

        timeouts_any = b.get("pending_timeouts")
        if isinstance(timeouts_any, list):
            restored_timeouts: dict[int, dict[str, Json]] = {}
            for item in timeouts_any:
                if not isinstance(item, dict):
                    continue
                view = _as_int(item.get("view"), -1)
                timeouts_list = item.get("timeouts")
                if view < 0 or not isinstance(timeouts_list, list):
                    continue
                bucket: dict[str, Json] = {}
                for tj in timeouts_list[: max(1, int(self.max_timeouts_per_bucket))]:
                    if not isinstance(tj, dict):
                        continue
                    signer = _as_str(tj.get("signer") or "")
                    if signer and signer not in bucket:
                        bucket[signer] = dict(tj)
                if bucket:
                    restored_timeouts[int(view)] = bucket
            self._timeouts = restored_timeouts

        self._prune_local_liveness_caches()

    def export_state(self) -> Json:
        out: Json = {
            "view": int(self.view),
            "finalized_block_id": self.finalized_block_id,
            "finalized_view": int(self.finalized_view),
            "last_voted_view": int(self.last_voted_view),
            "last_voted_block_id": self.last_voted_block_id,
            "last_proposed_view": int(self.last_proposed_view),
            "last_proposed_block_id": self.last_proposed_block_id,
            "last_progress_ms": int(self.last_progress_ms),
            "timeout_base_ms": int(self.timeout_base_ms),
            "timeout_backoff_exp": int(self.timeout_backoff_exp),
            "timeout_backoff_cap": int(self.timeout_backoff_cap),
            "last_timeout_view": int(self.last_timeout_view),
        }
        if self.high_qc is not None:
            out["high_qc"] = self.high_qc.to_json()
        if self.locked_qc is not None:
            out["locked_qc"] = self.locked_qc.to_json()
        if self.last_timeout_certificate is not None:
            out["last_timeout_certificate"] = self.last_timeout_certificate.to_json()
        pending_votes: list[Json] = []
        for key in sorted(
            self._votes.keys(), key=lambda item: (int(item[0]), str(item[1]), str(item[2]))
        ):
            bucket = self._votes.get(key) or {}
            votes = [
                dict(bucket[s]) for s in sorted(bucket.keys()) if isinstance(bucket.get(s), dict)
            ]
            if not votes:
                continue
            pending_votes.append(
                {
                    "view": int(key[0]),
                    "block_id": str(key[1]),
                    "block_hash": str(key[2]),
                    "votes": votes[: max(1, int(self.max_votes_per_bucket))],
                }
            )
        if pending_votes:
            out["pending_votes"] = pending_votes[-max(1, int(self.max_persisted_vote_buckets)) :]
        pending_timeouts: list[Json] = []
        for view in sorted(self._timeouts.keys()):
            bucket = self._timeouts.get(int(view)) or {}
            timeouts = [
                dict(bucket[s]) for s in sorted(bucket.keys()) if isinstance(bucket.get(s), dict)
            ]
            if not timeouts:
                continue
            pending_timeouts.append(
                {
                    "view": int(view),
                    "timeouts": timeouts[: max(1, int(self.max_timeouts_per_bucket))],
                }
            )
        if pending_timeouts:
            out["pending_timeouts"] = pending_timeouts[
                -max(1, int(self.max_persisted_timeout_buckets)) :
            ]
        return out

    def dump_to_state(self, state: Json) -> None:
        if not isinstance(state, dict):
            return
        state["bft"] = self.export_state()

    def _prune_local_liveness_caches(self) -> None:
        current_view = int(self.view)

        vote_items = sorted(
            self._votes.items(),
            key=lambda item: (int(item[0][0]), str(item[0][1]), str(item[0][2])),
        )
        pruned_votes: dict[tuple[int, str, str], dict[str, Json]] = {}
        for key, bucket in vote_items:
            view = int(key[0])
            if view + 2 < current_view:
                continue
            compact: dict[str, Json] = {}
            for signer in sorted(bucket.keys())[: max(1, int(self.max_votes_per_bucket))]:
                payload = bucket.get(signer)
                if isinstance(payload, dict):
                    compact[str(signer)] = dict(payload)
            if compact:
                pruned_votes[key] = compact
        if len(pruned_votes) > int(self.max_persisted_vote_buckets):
            keep = list(
                sorted(
                    pruned_votes.keys(), key=lambda item: (int(item[0]), str(item[1]), str(item[2]))
                )
            )[-int(self.max_persisted_vote_buckets) :]
            pruned_votes = {k: pruned_votes[k] for k in keep}
        self._votes = pruned_votes

        timeout_items = sorted((int(view), bucket) for view, bucket in self._timeouts.items())
        pruned_timeouts: dict[int, dict[str, Json]] = {}
        for view, bucket in timeout_items:
            if int(view) + 1 < current_view:
                continue
            compact: dict[str, Json] = {}
            for signer in sorted(bucket.keys())[: max(1, int(self.max_timeouts_per_bucket))]:
                payload = bucket.get(signer)
                if isinstance(payload, dict):
                    compact[str(signer)] = dict(payload)
            if compact:
                pruned_timeouts[int(view)] = compact
        if len(pruned_timeouts) > int(self.max_persisted_timeout_buckets):
            keep_views = list(sorted(pruned_timeouts.keys()))[
                -int(self.max_persisted_timeout_buckets) :
            ]
            pruned_timeouts = {int(v): pruned_timeouts[int(v)] for v in keep_views}
        self._timeouts = pruned_timeouts

    def pacemaker_timeout_ms(self) -> int:
        exp = max(0, min(int(self.timeout_backoff_exp), int(self.timeout_backoff_cap)))
        return int(self.timeout_base_ms) * (2**exp)

    def note_timeout_emitted(self, *, view: int) -> None:
        v = int(view)
        if v > int(self.last_timeout_view):
            self.last_timeout_view = v
        if v >= int(self.view):
            self.timeout_backoff_exp = min(
                int(self.timeout_backoff_exp) + 1, int(self.timeout_backoff_cap)
            )

    def note_progress(self) -> None:
        self.last_progress_ms = _now_ms()
        self.timeout_backoff_exp = 0

    def best_timeout_certificate(self) -> TimeoutCertificate | None:
        tc = self.last_timeout_certificate
        if tc is None:
            return None
        if tc.chain_id != self.chain_id:
            return None
        return tc

    # ---- core rules ----

    def bump_view(self, new_view: int) -> None:
        v = int(new_view)
        if v > self.view:
            self.view = v
            self.last_progress_ms = _now_ms()
            self.timeout_backoff_exp = 0
            self._prune_local_liveness_caches()

    def can_vote_for(
        self,
        *,
        blocks: dict[str, Any],
        block_id: str,
        justify_qc: QuorumCert | None = None,
    ) -> bool:
        """
        HotStuff safe-node rule.

        A node may vote for a proposal when either:
          - the proposed block extends the currently locked block, or
          - the proposal carries a justify QC whose view is strictly higher than
            the current lock view.

        The higher-justify branch is required for liveness during view changes
        and delayed message delivery. Restricting votes only to descendants of
        the current lock can strand honest validators on recoverable stalls.
        """
        bid = str(block_id).strip()
        if not bid:
            return False

        lock = self.locked_qc
        if lock is None or not str(lock.block_id or "").strip():
            return True

        locked_block_id = str(lock.block_id).strip()
        if is_descendant(blocks, candidate=bid, ancestor=locked_block_id):
            return True

        if justify_qc is None:
            return False
        if str(justify_qc.chain_id or "") != self.chain_id:
            return False

        try:
            justify_view = int(justify_qc.view)
            locked_view = int(lock.view)
        except Exception:
            return False

        if justify_view > locked_view:
            return True

        justify_block_id = str(justify_qc.block_id or "").strip()
        if justify_block_id and is_descendant(
            blocks, candidate=justify_block_id, ancestor=locked_block_id
        ):
            return True
        return False

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
        if (
            v == int(self.last_voted_view)
            and self.last_voted_block_id
            and bid != self.last_voted_block_id
        ):
            return False

        self.last_voted_view = v
        self.last_voted_block_id = bid
        return True

    def record_local_proposal(self, *, view: int, block_id: str) -> bool:
        """Record a local proposal if safe.

        Safety rules mirror local vote safety so a restarted leader cannot sign two
        different proposals for the same view. Re-emitting the same proposal for the
        same view is treated as idempotent and is allowed.
        """
        v = int(view)
        bid = str(block_id).strip()
        if not bid:
            return False

        if v < int(self.last_proposed_view):
            return False

        if (
            v == int(self.last_proposed_view)
            and self.last_proposed_block_id
            and bid != self.last_proposed_block_id
        ):
            return False

        self.last_proposed_view = v
        self.last_proposed_block_id = bid
        return True

    def observe_qc(self, *, blocks: dict[str, Any], qc: QuorumCert) -> str | None:
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
            if is_descendant(
                blocks, candidate=str(qc.block_id), ancestor=str(self.locked_qc.block_id)
            ):
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

        # finalize b1 if higher view than current finalized and it does not regress
        # away from an already-finalized chain. This keeps finalization monotonic
        # across restarts and delayed messages.
        if int(qc.view) >= int(self.finalized_view) and b1 and b1 != self.finalized_block_id:
            if self.finalized_block_id and not is_descendant(
                blocks, candidate=b1, ancestor=self.finalized_block_id
            ):
                return None
            self.finalized_block_id = b1
            self.finalized_view = int(qc.view)
            self.note_progress()
            return b1
        return None

    # ---- vote aggregation ----

    def accept_vote(
        self, *, vote_json: Json, validators: list[str], vpub: dict[str, str]
    ) -> QuorumCert | None:
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
            block_hash=_as_str(vote_json.get("block_hash") or ""),
            parent_id=_as_str(vote_json.get("parent_id") or ""),
            signer=_as_str(vote_json.get("signer") or ""),
            pubkey=_as_str(vote_json.get("pubkey") or ""),
            sig=_as_str(vote_json.get("sig") or ""),
            validator_epoch=_as_int(vote_json.get("validator_epoch"), 0),
            validator_set_hash=_as_str(vote_json.get("validator_set_hash") or ""),
        )
        if vote.chain_id != self.chain_id:
            return None
        if not vote.block_id or not vote.block_hash or not vote.signer:
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
            block_hash=vote.block_hash,
            parent_id=vote.parent_id,
            signer=vote.signer,
            pubkey=pubkey,
            sig=vote.sig,
            validator_epoch=int(vote.validator_epoch),
            validator_set_hash=vote.validator_set_hash,
        )
        if not vote2.verify():
            return None

        key = (int(vote2.view), vote2.block_id, vote2.block_hash)
        bucket = self._votes.get(key)
        if bucket is None:
            bucket = {}
            self._votes[key] = bucket
        # cache only first per signer (prevents duplicates)
        if vote2.signer not in bucket:
            bucket[vote2.signer] = vote2.to_json()
        self._prune_local_liveness_caches()

        th = quorum_threshold(len(vset))
        if len(bucket) >= th:
            qc = QuorumCert(
                chain_id=self.chain_id,
                view=int(vote2.view),
                block_id=vote2.block_id,
                block_hash=vote2.block_hash,
                parent_id=vote2.parent_id,
                votes=tuple(bucket.values()),
                validator_epoch=int(vote2.validator_epoch),
                validator_set_hash=vote2.validator_set_hash,
            )
            # QC should verify as a whole.
            if verify_qc(qc=qc, validators=validators, vpub=vpub, require_threshold=True):
                self.last_progress_ms = _now_ms()
                return qc
        return None

    # ---- timeout aggregation ----

    def accept_timeout(
        self, *, timeout_json: Json, validators: list[str], vpub: dict[str, str]
    ) -> int | None:
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
            validator_epoch=_as_int(timeout_json.get("validator_epoch"), 0),
            validator_set_hash=_as_str(timeout_json.get("validator_set_hash") or ""),
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
            validator_epoch=int(tmo.validator_epoch),
            validator_set_hash=tmo.validator_set_hash,
        )
        if not tmo2.verify():
            return None

        v = int(tmo2.view)
        if v < int(self.view):
            return None
        bucket = self._timeouts.get(v)
        if bucket is None:
            bucket = {}
            self._timeouts[v] = bucket
        if tmo2.signer not in bucket:
            bucket[tmo2.signer] = tmo2.to_json()
        self._prune_local_liveness_caches()

        th = quorum_threshold(len(vset))
        if len(bucket) >= th:
            high_qc_counts: dict[str, int] = {}
            for item in bucket.values():
                if not isinstance(item, dict):
                    continue
                qid = _as_str(item.get("high_qc_id") or "")
                if not qid:
                    continue
                high_qc_counts[qid] = int(high_qc_counts.get(qid, 0)) + 1

            chosen_high_qc_id = ""
            if high_qc_counts:
                chosen_high_qc_id = sorted(
                    high_qc_counts.items(), key=lambda kv: (-int(kv[1]), str(kv[0]))
                )[0][0]
            elif self.high_qc is not None:
                chosen_high_qc_id = str(self.high_qc.block_id or "")

            signers = tuple(sorted(str(s) for s in bucket.keys() if str(s)))
            self.last_timeout_certificate = TimeoutCertificate(
                chain_id=self.chain_id,
                view=int(v),
                high_qc_id=str(chosen_high_qc_id or ""),
                signer_count=len(signers),
                signers=signers,
                validator_epoch=int(tmo2.validator_epoch),
                validator_set_hash=str(tmo2.validator_set_hash or ""),
            )

            new_view = v + 1
            self.bump_view(new_view)
            self.note_progress()
            try:
                stale = [vv for vv in self._timeouts.keys() if int(vv) <= v]
                for vv in stale:
                    del self._timeouts[int(vv)]
            except Exception:
                pass
            self._prune_local_liveness_caches()
            return new_view
        return None
