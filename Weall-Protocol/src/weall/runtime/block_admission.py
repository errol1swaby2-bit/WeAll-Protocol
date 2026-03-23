import os
from dataclasses import dataclass
from typing import Any

from weall.ledger.state import LedgerView
from weall.runtime.ancestry import walk_ancestry
from weall.runtime.bft_hotstuff import validator_set_hash as _canonical_validator_set_hash
from weall.runtime.parallel_execution import verify_block_helper_plan_metadata
from weall.runtime.tx_admission import TxEnvelope, TxVerdict, admit_tx
from weall.tx.canon import TxIndex

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class BlockReject:
    code: str
    reason: str
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TxReject:
    code: str
    reason: str
    details: dict[str, Any]


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _get_active_validators_from_state(state: Json) -> list[str]:
    # Primary source: state["roles"]["validators"]["active_set"]
    roles = state.get("roles")
    if isinstance(roles, dict):
        validators = roles.get("validators")
        if isinstance(validators, dict):
            aset = validators.get("active_set")
            if isinstance(aset, list):
                out: list[str] = []
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
                out2: list[str] = []
                seen2: set[str] = set()
                for x in aset:
                    s = _as_str(x)
                    if not s or s in seen2:
                        continue
                    seen2.add(s)
                    out2.append(s)
                return out2
    return []


def _get_validator_pubkeys_from_state(state: Json) -> dict[str, str]:
    # consensus.apply.consensus.py stores validators under state["consensus"]["validators"]["registry"]
    out: dict[str, str] = {}
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


def _validator_set_hash_from_validators(validators: list[str]) -> str:
    """Return the canonical validator-set hash used by HotStuff and handshake paths.

    Consensus safety requires every caller in the codebase to derive the same
    set hash from the same logical validator set. Do not introduce ad-hoc
    encodings here; route through the canonical HotStuff helper instead.
    """
    return _canonical_validator_set_hash(list(validators or []))


def _current_validator_epoch_from_state(state: Json) -> int:
    c = state.get("consensus")
    if isinstance(c, dict):
        ep = c.get("epochs")
        if isinstance(ep, dict):
            cur = _as_int(ep.get("current"), 0)
            if cur > 0:
                return cur
        vs = c.get("validator_set")
        if isinstance(vs, dict):
            cur2 = _as_int(vs.get("epoch"), 0)
            if cur2 > 0:
                return cur2
    return 0


def _current_validator_set_hash_from_state(state: Json) -> str:
    c = state.get("consensus")
    if isinstance(c, dict):
        vs = c.get("validator_set")
        if isinstance(vs, dict):
            have = _as_str(vs.get("set_hash") or "")
            if have:
                return have
    return _validator_set_hash_from_validators(_get_active_validators_from_state(state))


def _block_view(block: Json) -> int:
    hdr = block.get("header") if isinstance(block.get("header"), dict) else {}
    return _as_int(
        block.get("view") or block.get("bft_view") or hdr.get("view") or hdr.get("bft_view"), 0
    )


def _block_proposer(block: Json) -> str:
    hdr = block.get("header") if isinstance(block.get("header"), dict) else {}
    return _as_str(
        block.get("proposer")
        or block.get("node_id")
        or hdr.get("proposer")
        or hdr.get("node_id")
        or ""
    )


def _validate_helper_execution_metadata(block: Json) -> tuple[bool, BlockReject | None]:
    helper_execution = block.get("helper_execution")
    if helper_execution is None:
        return True, None
    if not isinstance(helper_execution, dict):
        return False, BlockReject("bad_shape", "helper_execution_must_be_object", {"type": str(type(helper_execution))})
    advertised_plan_id = _as_str(helper_execution.get("plan_id") or "")
    ok, reason = verify_block_helper_plan_metadata(helper_execution=helper_execution, expected_plan_id=advertised_plan_id)
    if not ok:
        return False, BlockReject("helper_plan_invalid", str(reason), {"block_id": _as_str(block.get("block_id") or ""), "plan_id": advertised_plan_id})
    return True, None

def _validate_bft_proposal_leader_view(block: Json, state: Json) -> tuple[bool, BlockReject | None]:
    validators = _get_active_validators_from_state(state)
    if not validators:
        return False, BlockReject("bft_no_validators", "validator_set_empty", {})

    view = _block_view(block)
    proposer = _block_proposer(block)
    if view < 0:
        return False, BlockReject("bft_bad_view", "proposal_view_invalid", {"view": view})
    if not proposer:
        return False, BlockReject(
            "bft_missing_proposer", "proposal_missing_proposer", {"view": view}
        )

    from weall.runtime.bft_hotstuff import leader_for_view

    expected_leader = _as_str(leader_for_view(validators, view) or "")
    if expected_leader and proposer != expected_leader:
        return False, BlockReject(
            "bft_wrong_leader",
            "proposal_proposer_not_expected_leader",
            {"view": view, "proposer": proposer, "expected_leader": expected_leader},
        )
    return True, None


def _block_is_on_or_after_finalized_path(
    block: Json, state: Json, blocks_map: dict[str, Any]
) -> tuple[bool, BlockReject | None]:
    """Return whether ``block`` is the finalized block or a descendant of it.

    Commit/apply admission must reject blocks that would move local execution
    behind finalized state or onto a competing branch. Accepting ancestors of
    the finalized head is incorrect once the node has finalized a later block.
    """
    bft = state.get("bft")
    if not isinstance(bft, dict):
        return True, None
    finalized = _as_str(bft.get("finalized_block_id") or "")
    bid = _as_str(block.get("block_id") or "")
    if not finalized or not bid:
        return True, None
    if bid == finalized:
        return True, None
    if _is_descendant(blocks_map, candidate=bid, ancestor=finalized):
        return True, None
    return False, BlockReject(
        "bft_not_finalized",
        "block_not_on_finalized_path",
        {"block_id": bid, "finalized_block_id": finalized},
    )


def _parent_of(blocks: dict[str, Any], block_id: str) -> str:
    rec = blocks.get(str(block_id))
    if not isinstance(rec, dict):
        return ""
    return _as_str(rec.get("prev_block_id") or rec.get("prev") or "")


def _is_descendant(blocks: dict[str, Any], *, candidate: str, ancestor: str) -> bool:
    """Consensus-critical ancestry check without arbitrary depth limits.

    Block admission must agree with the HotStuff core and fork-choice logic on
    whether a block extends a finalized or locked branch. Fixed hop limits can
    make honest long-lived chains fail admission once they grow beyond the
    bound, even though the same branch still passes ancestry checks elsewhere in
    the stack. Route through the shared cycle-safe helper so every caller uses
    the same semantics.
    """

    return walk_ancestry(
        blocks,
        candidate=str(candidate).strip(),
        ancestor=str(ancestor).strip(),
        parent_of=lambda rec: (
            _parent_of(blocks, _as_str(rec.get("block_id") or ""))
            or _as_str(rec.get("prev_block_id") or rec.get("prev") or "")
        ),
    )


def admit_block_txs(
    txs: list[TxEnvelope],
    ledger: LedgerView,
    tx_index: TxIndex,
    *,
    max_block_txs: int = 50_000,
    verify_signatures: bool = True,
) -> tuple[bool, BlockReject | None, list[TxReject | None]]:
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
      - Calls runtime.tx_admission.admit_tx(..., context="block") for canon/gate checks.
      - Local candidate construction may set verify_signatures=False so unsigned
        dev/test fixtures can still build candidates, while remote apply/vote
        paths continue to verify signatures fail-closed.
    """
    if not isinstance(txs, list):
        return False, BlockReject("bad_shape", "txs_must_be_list", {"type": str(type(txs))}), []

    if len(txs) > int(max_block_txs):
        return (
            False,
            BlockReject(
                "too_large",
                "block_txs_exceeds_limit",
                {"count": len(txs), "max": int(max_block_txs)},
            ),
            [],
        )

    rejects: list[TxReject | None] = [None] * len(txs)

    # Enforce monotonic per-signer sequencing within this block for non-system txs.
    per_signer_next: dict[str, int] = {}
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

        verdict: TxVerdict = admit_tx(
            ledger=ledger,
            tx=env.to_json(),
            canon=tx_index,
            context="block" if bool(verify_signatures) else "local",
        )
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
) -> tuple[bool, BlockReject | None]:
    """BFT gating for incoming blocks.

    Feature flag:
      - Enabled when WEALL_BFT_ENABLED=1.

    Policy:
      - If not enabled: accept (no-op).
      - If enabled:
          * enforce validator epoch / validator set hash binding
          * enforce finalized-chain and locked-chain ancestry constraints
          * require justify_qc on proposals
          * verify justify_qc threshold + signatures
          * enforce deterministic proposal leader/view validity
    """
    if not _env_bool("WEALL_BFT_ENABLED", False):
        return True, None

    if not isinstance(block, dict):
        return False, BlockReject("bad_shape", "block_must_be_object", {"type": str(type(block))})

    ok_helper_meta, rej_helper_meta = _validate_helper_execution_metadata(block)
    if not ok_helper_meta:
        return False, rej_helper_meta

    blocks = state.get("blocks")
    blocks_map = blocks if isinstance(blocks, dict) else {}

    bid = _as_str(block.get("block_id") or "")
    prev = _as_str(block.get("prev_block_id") or block.get("prev") or "")

    local_epoch = _current_validator_epoch_from_state(state)
    block_epoch = _as_int(block.get("validator_epoch"), 0)
    if local_epoch > 0 and block_epoch > 0 and block_epoch != local_epoch:
        return (
            False,
            BlockReject(
                "bft_epoch_mismatch",
                "block_validator_epoch_mismatch",
                {"block_id": bid, "block_epoch": block_epoch, "local_epoch": local_epoch},
            ),
        )

    local_set_hash = _current_validator_set_hash_from_state(state)
    block_set_hash = _as_str(block.get("validator_set_hash") or "")
    if local_set_hash and block_set_hash and block_set_hash != local_set_hash:
        return (
            False,
            BlockReject(
                "bft_validator_set_mismatch",
                "block_validator_set_hash_mismatch",
                {
                    "block_id": bid,
                    "block_set_hash": block_set_hash,
                    "local_set_hash": local_set_hash,
                },
            ),
        )

    if not bid:
        return False, BlockReject("bad_shape", "missing_block_id", {})

    # Finality constraints (fail closed). Lock handling happens after justify_qc verification
    # so HotStuff safe-node exceptions can be evaluated correctly.
    bft = state.get("bft")
    if isinstance(bft, dict):
        finalized = _as_str(bft.get("finalized_block_id") or "")
        if finalized:
            if bid in blocks_map:
                # already known, must be on finalized chain
                if not _is_descendant(blocks_map, candidate=bid, ancestor=finalized):
                    return (
                        False,
                        BlockReject(
                            "bft_conflict",
                            "block_not_descendant_of_finalized",
                            {"block_id": bid, "finalized": finalized},
                        ),
                    )
            else:
                # unknown block: use prev linkage as a minimum check
                if prev and prev != finalized and prev in blocks_map:
                    if not _is_descendant(blocks_map, candidate=prev, ancestor=finalized):
                        return (
                            False,
                            BlockReject(
                                "bft_conflict",
                                "parent_not_descendant_of_finalized",
                                {"parent": prev, "finalized": finalized},
                            ),
                        )

    justify_qc = block.get("justify_qc")

    if justify_qc is None:
        if _mode() != "prod" and _env_bool("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", False):
            ok_view, rej_view = _validate_bft_proposal_leader_view(block, state)
            if not ok_view:
                return False, rej_view
            return True, None
        return False, BlockReject(
            "bft_missing_qc", "bft_enabled_requires_justify_qc", {"block_id": bid}
        )

    if not isinstance(justify_qc, dict):
        return False, BlockReject(
            "bad_shape", "justify_qc_must_be_object", {"type": str(type(justify_qc))}
        )

    ok_view, rej_view = _validate_bft_proposal_leader_view(block, state)
    if not ok_view:
        return False, rej_view

    from weall.runtime.bft_hotstuff import qc_from_json, verify_qc

    chain_id = _as_str(state.get("chain_id") or block.get("chain_id") or "")
    if not chain_id:
        return False, BlockReject("bad_state", "missing_chain_id", {})

    validators = _get_active_validators_from_state(state)
    if not validators:
        return False, BlockReject("bft_no_validators", "validator_set_empty", {})

    qc_epoch = _as_int(justify_qc.get("validator_epoch"), 0)
    if local_epoch > 0 and qc_epoch > 0 and qc_epoch != local_epoch:
        return False, BlockReject(
            "bft_epoch_mismatch",
            "justify_qc_validator_epoch_mismatch",
            {"qc_epoch": qc_epoch, "local_epoch": local_epoch},
        )

    qc_set_hash = _as_str(justify_qc.get("validator_set_hash") or "")
    if local_set_hash and qc_set_hash and qc_set_hash != local_set_hash:
        return False, BlockReject(
            "bft_validator_set_mismatch",
            "justify_qc_validator_set_hash_mismatch",
            {"qc_set_hash": qc_set_hash, "local_set_hash": local_set_hash},
        )

    qc = qc_from_json(justify_qc)
    if qc is None:
        return False, BlockReject("bft_bad_qc", "justify_qc_invalid_shape", {"block_id": bid})
    if str(qc.chain_id or "") != chain_id:
        return False, BlockReject(
            "bft_bad_qc",
            "justify_qc_chain_id_mismatch",
            {"qc_chain_id": str(qc.chain_id or ""), "chain_id": chain_id},
        )
    if prev and str(qc.block_id or "") != prev:
        return False, BlockReject(
            "bft_bad_qc",
            "justify_qc_block_id_mismatch",
            {"expected_parent": prev, "justify_qc_block_id": str(qc.block_id or "")},
        )

    vpub = _get_validator_pubkeys_from_state(state)
    if not verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub):
        return False, BlockReject(
            "bft_qc_insufficient",
            "justify_qc_threshold_not_met",
            {"block_id": bid, "justify_qc_block_id": str(qc.block_id or "")},
        )

    locked_qc = bft.get("locked_qc") if isinstance(bft, dict) else None
    if isinstance(locked_qc, dict):
        locked_bid = _as_str(locked_qc.get("block_id") or "")
        locked_view = _as_int(locked_qc.get("view"), 0)
        if locked_bid:
            extends_lock = False
            if bid in blocks_map:
                extends_lock = _is_descendant(blocks_map, candidate=bid, ancestor=locked_bid)
            elif prev and prev in blocks_map:
                extends_lock = (
                    _is_descendant(blocks_map, candidate=prev, ancestor=locked_bid)
                    or prev == locked_bid
                )

            justify_advances_lock = int(qc.view) > int(locked_view)

            if not extends_lock and not justify_advances_lock:
                return (
                    False,
                    BlockReject(
                        "bft_conflict",
                        "block_not_safe_under_lock",
                        {
                            "block_id": bid,
                            "locked": locked_bid,
                            "locked_view": int(locked_view),
                            "justify_qc_block_id": str(qc.block_id or ""),
                            "justify_qc_view": int(qc.view),
                        },
                    ),
                )

    if isinstance(block.get("qc"), dict):
        return False, BlockReject(
            "bft_bad_qc", "proposal_must_not_embed_self_qc", {"block_id": bid}
        )

    return True, None


def admit_bft_commit_block(
    *,
    block: Json,
    state: Json,
    blocks_map: dict[str, Any] | None = None,
) -> tuple[bool, BlockReject | None]:
    """Final commit/apply admission for BFT mode.

    This is stricter than proposal admission: the block must already satisfy proposal
    validity and must also lie on the currently finalized path known to the node.
    The caller may supply a speculative ``blocks_map`` containing pending proposals so
    ancestry checks remain deterministic before all blocks are durably committed.
    """
    ok, rej = admit_bft_block(block=block, state=state)
    if not ok:
        return ok, rej

    if not _env_bool("WEALL_BFT_ENABLED", False):
        return True, None

    effective_blocks = blocks_map if isinstance(blocks_map, dict) else {}
    if not effective_blocks:
        raw_blocks = state.get("blocks")
        effective_blocks = raw_blocks if isinstance(raw_blocks, dict) else {}

    ok_fin, rej_fin = _block_is_on_or_after_finalized_path(block, state, effective_blocks)
    if not ok_fin:
        return False, rej_fin

    return True, None
