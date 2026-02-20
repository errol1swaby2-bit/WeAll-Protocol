# src/weall/runtime/block_admission.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import TxEnvelope, TxVerdict, admit_tx
from weall.tx.canon import TxIndex

Json = Dict[str, Any]


@dataclass(frozen=True, slots=True)
class BlockReject:
    code: str
    reason: str
    details: Dict[str, Any]


@dataclass(frozen=True, slots=True)
class TxReject:
    code: str
    reason: str
    details: Dict[str, Any]


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _get_active_validators_from_state(state: Json) -> List[str]:
    # Primary source: state["roles"]["validators"]["active_set"]
    roles = state.get("roles")
    if isinstance(roles, dict):
        validators = roles.get("validators")
        if isinstance(validators, dict):
            aset = validators.get("active_set")
            if isinstance(aset, list):
                out: List[str] = []
                seen: set[str] = set()
                for x in aset:
                    s = _as_str(x)
                    if not s or s in seen:
                        continue
                    seen.add(s)
                    out.append(s)
                return out
    # Fallback: state["consensus"]["validator_set"]["active_set"]
    c = state.get("consensus")
    if isinstance(c, dict):
        vs = c.get("validator_set")
        if isinstance(vs, dict):
            aset = vs.get("active_set")
            if isinstance(aset, list):
                out2: List[str] = []
                seen2: set[str] = set()
                for x in aset:
                    s = _as_str(x)
                    if not s or s in seen2:
                        continue
                    seen2.add(s)
                    out2.append(s)
                return out2
    return []


def _get_validator_pubkeys_from_state(state: Json) -> Dict[str, str]:
    # consensus.apply.consensus.py stores validators under state["consensus"]["validators"]["registry"]
    out: Dict[str, str] = {}
    c = state.get("consensus")
    if not isinstance(c, dict):
        return out
    v = c.get("validators")
    if not isinstance(v, dict):
        return out
    reg = v.get("registry")
    if not isinstance(reg, dict):
        return out
    for acct, rec in reg.items():
        acct_s = _as_str(acct)
        if not acct_s or not isinstance(rec, dict):
            continue
        pk = _as_str(rec.get("pubkey") or "")
        if pk:
            out[acct_s] = pk
    return out


def _parent_of(blocks: Dict[str, Any], block_id: str) -> str:
    rec = blocks.get(str(block_id))
    if not isinstance(rec, dict):
        return ""
    return _as_str(rec.get("prev_block_id") or rec.get("prev") or "")


def _is_descendant(blocks: Dict[str, Any], *, candidate: str, ancestor: str, max_hops: int = 50_000) -> bool:
    cand = str(candidate).strip()
    anc = str(ancestor).strip()
    if not cand or not anc:
        return False
    if cand == anc:
        return True
    cur = cand
    hops = 0
    while hops < int(max_hops):
        hops += 1
        parent = _parent_of(blocks, cur)
        if not parent:
            return False
        if parent == anc:
            return True
        cur = parent
    return False


def admit_block_txs(
    txs: List[TxEnvelope],
    ledger: LedgerView,
    tx_index: TxIndex,
    *,
    max_block_txs: int = 50_000,
) -> Tuple[bool, Optional[BlockReject], List[Optional[TxReject]]]:
    """
    Deterministic block-context admission for a list of tx envelopes.

    Returns:
      ok,
      block_reject (fatal; if not None, the caller should reject the whole block),
      per_tx_rejects list (aligned with txs; None means admitted).

    Policy:
      - Non-system txs must have sequential per-signer nonces within the block
        starting from chain_nonce + 1.
      - System txs are allowed with nonce=0 and are exempt from per-signer sequencing.
      - Duplicate signer+nonce for non-system txs is rejected deterministically.
      - Calls runtime.tx_admission.admit_tx(..., context="block") for canon/gate/sig checks.
    """
    if not isinstance(txs, list):
        return False, BlockReject("bad_shape", "txs_must_be_list", {"type": str(type(txs))}), []

    if len(txs) > int(max_block_txs):
        return (
            False,
            BlockReject("too_large", "block_txs_exceeds_limit", {"count": len(txs), "max": int(max_block_txs)}),
            [],
        )

    rejects: List[Optional[TxReject]] = [None] * len(txs)

    # Enforce monotonic per-signer sequencing within this block for non-system txs.
    per_signer_next: Dict[str, int] = {}
    seen_signer_nonce: set[tuple[str, int]] = set()

    for i, env in enumerate(txs):
        # Fail closed but deterministic: if the element isn't a TxEnvelope, mark rejected.
        if not isinstance(env, TxEnvelope):
            rejects[i] = TxReject(
                code="bad_shape",
                reason="tx_must_be_TxEnvelope",
                details={"index": i, "type": str(type(env))},
            )
            continue

        verdict: TxVerdict = admit_tx(ledger=ledger, tx=env.to_json(), canon=tx_index, context="block")
        if not verdict.ok:
            rejects[i] = TxReject(code=verdict.code, reason=verdict.reason, details=verdict.details)
            continue

        # SYSTEM txs: allow nonce=0 and skip sequencing rules.
        if bool(getattr(env, "system", False)):
            if int(env.nonce) != 0:
                rejects[i] = TxReject(
                    code="bad_nonce",
                    reason="system_tx_nonce_must_be_zero",
                    details={"index": i, "signer": env.signer, "have": int(env.nonce)},
                )
            continue

        signer = env.signer
        chain_nonce = ledger.get_nonce(signer)
        expected = per_signer_next.get(signer, chain_nonce + 1)

        # Duplicate protection: same signer+nonce repeated in a block is rejected.
        key = (signer, int(env.nonce))
        if key in seen_signer_nonce:
            rejects[i] = TxReject(
                code="duplicate",
                reason="duplicate_signer_nonce_in_block",
                details={"signer": signer, "nonce": int(env.nonce)},
            )
            continue

        if int(env.nonce) != int(expected):
            rejects[i] = TxReject(
                code="bad_nonce",
                reason="nonce_not_sequential_in_block",
                details={
                    "signer": signer,
                    "have": int(env.nonce),
                    "expected": int(expected),
                    "chain_nonce": int(chain_nonce),
                },
            )
            continue

        seen_signer_nonce.add(key)
        per_signer_next[signer] = int(expected) + 1

    # No fatal rejection by default (consensus may permit empty blocks).
    return True, None, rejects


# -----------------------------
# BFT-aware block admission
# -----------------------------

def admit_bft_block(
    *,
    block: Json,
    state: Json,
) -> Tuple[bool, Optional[BlockReject]]:
    """BFT gating for incoming blocks.

    Feature flag:
      - Enabled when WEALL_BFT_ENABLED=1.

    Current policy (incremental rollout):
      - If not enabled: accept (no-op).
      - If enabled:
          * If state has bft.finalized_block_id: require candidate block is descendant.
          * If state has bft.locked_qc.block_id: require candidate block is descendant.
          * If block includes a QC under block["qc"]: verify threshold + signatures.

    IMPORTANT:
      - This function does not yet enforce view/leader rules for proposals.
        That wiring will be done in the networking layer once BFT packets are live.
    """
    if not _env_bool("WEALL_BFT_ENABLED", False):
        return True, None

    if not isinstance(block, dict):
        return False, BlockReject("bad_shape", "block_must_be_object", {"type": str(type(block))})

    blocks = state.get("blocks")
    blocks_map = blocks if isinstance(blocks, dict) else {}

    bid = _as_str(block.get("block_id") or "")
    prev = _as_str(block.get("prev_block_id") or block.get("prev") or "")

    if not bid:
        return False, BlockReject("bad_shape", "missing_block_id", {})

    # Finality + lock ancestry constraints (fail closed).
    bft = state.get("bft")
    if isinstance(bft, dict):
        finalized = _as_str(bft.get("finalized_block_id") or "")
        if finalized:
            if bid in blocks_map:
                # already known, must be on finalized chain
                if not _is_descendant(blocks_map, candidate=bid, ancestor=finalized):
                    return (
                        False,
                        BlockReject("bft_conflict", "block_not_descendant_of_finalized", {"block_id": bid, "finalized": finalized}),
                    )
            else:
                # unknown block: use prev linkage as a minimum check
                if prev and prev != finalized and prev in blocks_map:
                    if not _is_descendant(blocks_map, candidate=prev, ancestor=finalized):
                        return (
                            False,
                            BlockReject("bft_conflict", "parent_not_descendant_of_finalized", {"parent": prev, "finalized": finalized}),
                        )

        locked_qc = bft.get("locked_qc")
        if isinstance(locked_qc, dict):
            locked_bid = _as_str(locked_qc.get("block_id") or "")
            if locked_bid:
                if bid in blocks_map:
                    if not _is_descendant(blocks_map, candidate=bid, ancestor=locked_bid):
                        return (
                            False,
                            BlockReject("bft_conflict", "block_not_descendant_of_lock", {"block_id": bid, "locked": locked_bid}),
                        )
                else:
                    if prev and prev != locked_bid and prev in blocks_map:
                        if not _is_descendant(blocks_map, candidate=prev, ancestor=locked_bid):
                            return (
                                False,
                                BlockReject("bft_conflict", "parent_not_descendant_of_lock", {"parent": prev, "locked": locked_bid}),
                            )

    qc = block.get("qc")
    if qc is None:
        # During rollout we allow QC-less blocks only if explicitly permitted.
        if _env_bool("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", False):
            return True, None
        return False, BlockReject("bft_missing_qc", "bft_enabled_requires_qc", {"block_id": bid})

    if not isinstance(qc, dict):
        return False, BlockReject("bad_shape", "qc_must_be_object", {"type": str(type(qc))})

    # Verify QC signatures and threshold
    from weall.runtime.bft_hotstuff import BftVote, quorum_threshold  # local import to keep startup light

    chain_id = _as_str(state.get("chain_id") or block.get("chain_id") or "")
    if not chain_id:
        return False, BlockReject("bad_state", "missing_chain_id", {})

    validators = _get_active_validators_from_state(state)
    thr = quorum_threshold(len(validators))
    if thr <= 0:
        return False, BlockReject("bft_no_validators", "validator_set_empty", {})

    qc_view = _as_int(qc.get("view"), 0)
    qc_block_id = _as_str(qc.get("block_id") or "")
    qc_parent_id = _as_str(qc.get("parent_id") or "")
    votes = _as_list(qc.get("votes"))

    if qc_block_id and qc_block_id != bid:
        return False, BlockReject("bft_bad_qc", "qc_block_id_mismatch", {"block_id": bid, "qc_block_id": qc_block_id})

    if qc_parent_id and prev and qc_parent_id != prev:
        return False, BlockReject("bft_bad_qc", "qc_parent_id_mismatch", {"prev": prev, "qc_parent_id": qc_parent_id})

    vpub = _get_validator_pubkeys_from_state(state)

    seen: set[str] = set()
    ok_votes = 0
    for vj in votes:
        if not isinstance(vj, dict):
            continue
        signer = _as_str(vj.get("signer") or "")
        pubkey = _as_str(vj.get("pubkey") or "")
        sig = _as_str(vj.get("sig") or "")
        if not signer or signer in seen:
            continue
        seen.add(signer)

        # If registry has a pubkey, it must match.
        expected = _as_str(vpub.get(signer) or "")
        if expected and pubkey and pubkey != expected:
            continue

        vote = BftVote(
            chain_id=chain_id,
            view=int(qc_view),
            block_id=bid,
            parent_id=prev or qc_parent_id or "",
            signer=signer,
            pubkey=pubkey or expected,
            sig=sig,
        )
        if vote.verify():
            ok_votes += 1

    if ok_votes < thr:
        return False, BlockReject("bft_qc_insufficient", "qc_threshold_not_met", {"have": ok_votes, "need": thr})

    return True, None

