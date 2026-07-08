# src/weall/runtime/system_tx_engine.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

# Rewards scheduling (Genesis v1.5): leaders enqueue deterministic epoch-issuance
# system txs inside the block. Followers never run the scheduler; they replay the
# included txs.
from weall.ledger.constants import MAX_SUPPLY, MINT_POOL_ACCOUNT_ID, TREASURY_ACCOUNT_ID
from weall.ledger.issuance import (
    cap_issuance_by_remaining_supply,
    epoch_issuance_subsidy_atomic,
    issuance_due_at_height,
    issuance_epoch_index_for_due_height,
)
from weall.ledger.roles_schema import ensure_roles_schema
from weall.runtime.bounded_rollback import journal_append_list, journal_set_dict_key
from weall.runtime.econ_phase import econ_allowed_from_state
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.reviewer_responsibilities import CONTENT_REVIEW_LANE, eligible_reviewer_ids
from weall.tx.canon import TxIndex

Json = dict[str, Any]


class SystemTxEngineError(RuntimeError):
    """Base error for consensus-adjacent system-tx scheduling and emission."""


class SystemSchedulerError(SystemTxEngineError):
    """Deterministic scheduler failed while preparing system tx side effects."""


class SystemQueueCorruptionError(SystemTxEngineError):
    """The replicated system queue contains malformed data and must fail closed."""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return int(default)


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except (TypeError, ValueError):
        return ""


def _as_opt_str(v: Any) -> str:
    """Like _as_str, but treats None as empty string (critical for parent refs)."""
    if v is None:
        return ""
    return _as_str(v)


def _canon_info(canon: Any, tx_type: str) -> dict[str, Any] | None:
    """Return canon entry for tx_type, supporting both TxIndex and lightweight dict stubs.

    TxIndex: canon.get(tx_type) -> dict|None
    Dict stub (tests): {"by_name": {tx_type: {...}}}
    Dict fallback: {tx_type: {...}}
    """
    tx_u = _as_str(tx_type).strip().upper()
    if not tx_u:
        return None

    if isinstance(canon, TxIndex):
        info = canon.get(tx_u)
        return info if isinstance(info, dict) else None

    if isinstance(canon, dict):
        by_name = canon.get("by_name")
        if isinstance(by_name, dict):
            info = by_name.get(tx_u)
            return info if isinstance(info, dict) else None

        info = canon.get(tx_u)
        return info if isinstance(info, dict) else None

    try:
        info = canon.get(tx_u)  # type: ignore[attr-defined]
    except AttributeError:
        return None
    return info if isinstance(info, dict) else None


def _canon_context(canon: Any, tx_type: str) -> str:
    info = _canon_info(canon, tx_type)
    ctx = _as_str(info.get("context", "") if isinstance(info, dict) else "")
    return ctx.strip().lower()


def _is_system_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    return bool(info.get("system_only") is True) if isinstance(info, dict) else False


def _is_receipt_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    return bool(info.get("receipt_only") is True) if isinstance(info, dict) else False


def _canon_parent_required(canon: Any, tx_type: str) -> str:
    """Return the canon-declared parent type (string) for receipt-only txs, if any."""
    info = _canon_info(canon, tx_type)
    if not isinstance(info, dict):
        return ""
    p = info.get("parent")
    return _as_opt_str(p).strip().upper()


# ---------------------------------------------------------------------------
# Rewards scheduling (Genesis v2.1)
# ---------------------------------------------------------------------------


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _uniq_strs(xs: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for it in xs:
        s = _as_str(it).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _reward_recipients(state: Json, proposer: str) -> dict[str, list[str]]:
    roles = ensure_roles_schema(state)

    node_ops = roles.get("node_operators") if isinstance(roles.get("node_operators"), dict) else {}
    jurors = roles.get("jurors") if isinstance(roles.get("jurors"), dict) else {}
    creators = roles.get("creators") if isinstance(roles.get("creators"), dict) else {}

    operators_set = _uniq_strs(_as_list(node_ops.get("active_set")))
    jurors_set = _uniq_strs(_as_list(jurors.get("active_set")))
    creators_set = _uniq_strs(_as_list(creators.get("active_set")))

    prop = str(proposer or "").strip()
    validators_set = [prop] if prop else []

    return {
        "validators": validators_set,
        "operators": operators_set,
        "jurors": jurors_set,
        "creators": creators_set,
    }


def _even_split(amount: int, recipients: list[str]) -> tuple[dict[str, int], int]:
    amt = int(amount)
    recips = [r for r in recipients if isinstance(r, str) and r.strip()]
    if amt <= 0 or not recips:
        return {}, amt
    n = len(recips)
    share = amt // n
    if share <= 0:
        return {}, amt
    payouts: dict[str, int] = {}
    for r in recips:
        payouts[r] = payouts.get(r, 0) + share
    remainder = amt - (share * n)
    return payouts, remainder


def _monetary_policy_snapshot(state: Json) -> dict[str, int]:
    econ = state.get("economics")
    if not isinstance(econ, dict):
        return {"issued": 0}
    mp = econ.get("monetary_policy")
    if not isinstance(mp, dict):
        return {"issued": 0}
    return {"issued": _as_int(mp.get("issued"), 0)}


def schedule_block_rewards_system_txs(
    state: Json,
    *,
    next_height: int,
    proposer: str,
    phase: str,
) -> None:
    """Enqueue Genesis v1.5 epoch issuance system txs.

    Gate:
      - During the Genesis economic lock OR when economics are disabled, issuance/rewards are not emitted.

    Cadence:
      - WeCoin issuance is epoch-based, not per-block. At the 20-second target
        block interval, one 10-minute issuance epoch closes every 30 blocks.

    Split:
      - 20/20/20/20/20 across validators/proposer, operators, jurors, creators, treasury.

    NOTE: Fees are not yet wired into the fee engine in this build, so fees default to 0.
    """

    phase_n = _as_str(phase).strip().lower() or "post"
    if phase_n != "post":
        return

    if not econ_allowed_from_state(state):
        return

    h = int(next_height)
    if h <= 0:
        return

    if not issuance_due_at_height(h):
        return

    issuance_epoch = issuance_epoch_index_for_due_height(h)
    epoch_id = f"issuance_epoch:{issuance_epoch}"
    reward_block_id = epoch_id

    mp = _monetary_policy_snapshot(state)
    issued = int(mp.get("issued", 0))

    raw_subsidy = int(epoch_issuance_subsidy_atomic(issuance_epoch))
    subsidy, _remaining_after = cap_issuance_by_remaining_supply(
        issued, raw_subsidy, max_supply=int(MAX_SUPPLY)
    )

    fee_total = 0
    total_reward = int(subsidy) + int(fee_total)
    if total_reward <= 0:
        return

    per_bucket = total_reward // 5
    buckets = {
        "validators": per_bucket,
        "operators": per_bucket,
        "jurors": per_bucket,
        "creators": per_bucket,
        "treasury": total_reward - (per_bucket * 4),
    }

    recips = _reward_recipients(state, proposer=str(proposer or "").strip())
    payouts: dict[str, int] = {}
    treasury_extra = 0

    for bucket_name in ("validators", "operators", "jurors", "creators"):
        amt = int(buckets.get(bucket_name, 0))
        rs = recips.get(bucket_name, [])
        sub_payouts, rem = _even_split(amt, list(rs))
        treasury_extra += int(rem)
        for acct_id, a in sub_payouts.items():
            payouts[acct_id] = payouts.get(acct_id, 0) + int(a)

    payouts[TREASURY_ACCOUNT_ID] = (
        payouts.get(TREASURY_ACCOUNT_ID, 0) + int(buckets.get("treasury", 0)) + int(treasury_extra)
    )

    transfers: list[Json] = []
    for acct_id in sorted(payouts.keys()):
        amt = int(payouts.get(acct_id, 0))
        if amt <= 0:
            continue
        transfers.append({"to": acct_id, "amount": amt})

    # Conservation: reward credits must be funded from a debit source.
    #
    # Today (Genesis lock build): fee_total is 0, so the full reward pool is
    # funded by newly minted subsidy.
    #
    # Future: when fees are wired, include fee pool debits as well.
    debits: list[Json] = []
    if total_reward > 0:
        debits.append({"from": MINT_POOL_ACCOUNT_ID, "amount": int(total_reward)})

    enqueue_system_tx(
        state,
        tx_type="BLOCK_REWARD_MINT",
        payload={
            "block_id": reward_block_id,
            "height": h,
            "issuance_epoch": int(issuance_epoch),
            "epoch_id": epoch_id,
            "amount": int(subsidy),
            "fees": int(fee_total),
            "total": int(total_reward),
            "proposer": str(proposer or "").strip(),
        },
        due_height=h,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    enqueue_system_tx(
        state,
        tx_type="BLOCK_REWARD_DISTRIBUTE",
        payload={
            "block_id": reward_block_id,
            "height": h,
            "issuance_epoch": int(issuance_epoch),
            "epoch_id": epoch_id,
            "subsidy": int(subsidy),
            "fees": int(fee_total),
            "total": int(total_reward),
            "proposer": str(proposer or "").strip(),
            "transfers": transfers,
            "debits": debits,
        },
        due_height=h,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )


@dataclass(frozen=True)
class SystemQueueItem:
    queue_id: str
    tx_type: str
    payload: Json
    signer: str
    due_height: int
    parent: str
    phase: str  # "pre" or "post"
    once: bool = True
    emitted_height: int | None = None

    def to_ledger_obj(self) -> Json:
        return {
            "queue_id": self.queue_id,
            "tx_type": self.tx_type,
            "payload": self.payload,
            "signer": self.signer,
            "due_height": self.due_height,
            "parent": self.parent,
            "phase": self.phase,
            "once": bool(self.once),
            "emitted_height": self.emitted_height,
        }

    @staticmethod
    def from_ledger_obj(obj: Any) -> SystemQueueItem:
        if not isinstance(obj, dict):
            raise ValueError("bad_system_queue_item")
        return SystemQueueItem(
            queue_id=_as_str(obj.get("queue_id")).strip(),
            tx_type=_as_str(obj.get("tx_type")).strip().upper(),
            payload=obj.get("payload") if isinstance(obj.get("payload"), dict) else {},
            signer=_as_str(obj.get("signer")).strip() or "SYSTEM",
            due_height=_as_int(obj.get("due_height"), 0),
            parent=_as_opt_str(obj.get("parent")).strip(),
            phase=_as_str(obj.get("phase")).strip().lower() or "post",
            once=bool(obj.get("once", True)),
            emitted_height=obj.get("emitted_height")
            if isinstance(obj.get("emitted_height"), int)
            else None,
        )


def _queue_root(state: Json) -> list[Json]:
    root = state.get("system_queue")
    if not isinstance(root, list):
        root = []
        journal_set_dict_key(state, "system_queue", root, "system_queue")
    return root


def _validated_queue_items_with_indexes(state: Json) -> list[tuple[int, SystemQueueItem]]:
    items: list[tuple[int, SystemQueueItem]] = []
    for idx, obj in enumerate(_queue_root(state)):
        if not isinstance(obj, dict):
            raise SystemQueueCorruptionError(f"system_queue_item_not_object:{idx}")
        try:
            item = SystemQueueItem.from_ledger_obj(obj)
        except (TypeError, ValueError) as exc:
            raise SystemQueueCorruptionError(f"system_queue_item_invalid:{idx}") from exc

        if not item.queue_id:
            raise SystemQueueCorruptionError(f"system_queue_item_missing_queue_id:{idx}")
        if item.phase not in {"pre", "post"}:
            raise SystemQueueCorruptionError(f"system_queue_item_bad_phase:{idx}")
        items.append((idx, item))
    return items


def _validated_queue_items(state: Json) -> list[SystemQueueItem]:
    return [item for _idx, item in _validated_queue_items_with_indexes(state)]


def build_system_queue_lookup(state: Json) -> dict[str, Json]:
    """Return a first-match queue-id lookup after validating the queue once.

    The returned values are the live ledger dictionaries, not copied dataclasses.
    That preserves the current in-place mutation behavior while allowing replay
    callers to avoid rescanning the whole queue for phase and binding checks.
    Duplicate queue IDs keep first-match semantics, matching the old linear scan.
    """
    lookup: dict[str, Json] = {}
    root = _queue_root(state)
    for idx, item in _validated_queue_items_with_indexes(state):
        if item.queue_id not in lookup:
            obj = root[idx]
            if isinstance(obj, dict):
                lookup[item.queue_id] = obj
    return lookup


def _lookup_queue_item(queue_objects_by_id: Mapping[str, Any] | None, qid: str) -> SystemQueueItem | None:
    if queue_objects_by_id is None:
        return None
    obj = queue_objects_by_id.get(qid)
    if obj is None:
        return None
    if not isinstance(obj, dict):
        raise SystemQueueCorruptionError("system_queue_lookup_item_not_object")
    try:
        item = SystemQueueItem.from_ledger_obj(obj)
    except (TypeError, ValueError) as exc:
        raise SystemQueueCorruptionError("system_queue_lookup_item_invalid") from exc
    if not item.queue_id:
        raise SystemQueueCorruptionError("system_queue_lookup_item_missing_queue_id")
    if item.phase not in {"pre", "post"}:
        raise SystemQueueCorruptionError("system_queue_lookup_item_bad_phase")
    return item


def system_queue_phase_for_id(state: Json, *, queue_id: str) -> str:
    qid = _as_str(queue_id).strip()
    if not qid:
        return ""
    for item in _validated_queue_items(state):
        if item.queue_id == qid:
            return str(item.phase).strip().lower()
    return ""


def _queue_ids(state: Json) -> set[str]:
    ids: set[str] = set()
    for obj in _queue_root(state):
        if isinstance(obj, dict):
            qid = _as_str(obj.get("queue_id")).strip()
            if qid:
                ids.add(qid)
    return ids


def enqueue_system_tx(
    state: Json,
    *,
    tx_type: str,
    payload: Json,
    due_height: int,
    signer: str = "SYSTEM",
    once: bool = True,
    parent: str | None = None,
    phase: str = "post",
) -> str:
    tx_type_u = _as_str(tx_type).strip().upper()
    phase_n = _as_str(phase).strip().lower() or "post"
    parent_norm = _as_opt_str(parent).strip() if parent is not None else ""

    base = {
        "tx_type": tx_type_u,
        "payload": payload or {},
        "signer": _as_str(signer).strip() or "SYSTEM",
        "due_height": int(due_height),
        "parent": parent_norm,
        "phase": phase_n,
        "once": bool(once),
    }

    raw = json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
    qid = hashlib.sha256(raw).hexdigest()
    base["queue_id"] = qid

    if qid in _queue_ids(state):
        return qid

    journal_append_list(_queue_root(state), base, "system_queue")
    return qid


def _select_due_items_with_indexes(state: Json, *, next_height: int, phase: str) -> list[tuple[int, SystemQueueItem]]:
    out: list[tuple[int, SystemQueueItem]] = []
    phase_n = _as_str(phase).strip().lower() or "post"
    for idx, item in _validated_queue_items_with_indexes(state):
        if item.emitted_height is not None and item.once:
            continue
        if item.phase != phase_n:
            continue
        if int(item.due_height) != int(next_height):
            continue

        out.append((idx, item))
    return out


def _select_due_items(state: Json, *, next_height: int, phase: str) -> list[SystemQueueItem]:
    return [item for _idx, item in _select_due_items_with_indexes(state, next_height=next_height, phase=phase)]



# ---------------------------------------------------------------------------
# Content-review assignment scheduling
# ---------------------------------------------------------------------------


def _identity_variants(value: Any) -> list[str]:
    s = _as_str(value).strip()
    if not s:
        return []
    base = s[1:] if s.startswith("@") else s
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (s, base, f"@{base}" if base else ""):
        c = _as_str(candidate).strip()
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _same_account(left: Any, right: Any) -> bool:
    left_variants = {v.lower().lstrip("@") for v in _identity_variants(left)}
    right_variants = {v.lower().lstrip("@") for v in _identity_variants(right)}
    return bool(left_variants and right_variants and left_variants.intersection(right_variants))


def _resolve_account_identity(state: Json, value: Any) -> str:
    variants = _identity_variants(value)
    if not variants:
        return ""
    accounts = state.get("accounts")
    if isinstance(accounts, dict):
        for variant in variants:
            if variant in accounts:
                return variant
    return variants[0]


def _content_target_owner_for_assignment(state: Json, dispute: Json) -> str:
    owner = _as_str(
        dispute.get("target_owner")
        or dispute.get("target_author")
        or dispute.get("content_author")
        or ""
    ).strip()
    if owner:
        return _resolve_account_identity(state, owner)

    target_id = _as_str(dispute.get("target_id") or dispute.get("target") or "").strip()
    if not target_id:
        return ""
    content = state.get("content")
    if not isinstance(content, dict):
        return ""
    for bucket_name in ("posts", "comments"):
        bucket = content.get(bucket_name)
        if not isinstance(bucket, dict):
            continue
        rec = bucket.get(target_id)
        if isinstance(rec, dict):
            return _resolve_account_identity(
                state,
                rec.get("author") or rec.get("owner") or rec.get("account_id") or rec.get("created_by"),
            )
    return ""


def _is_content_review_dispute(dispute: Json) -> bool:
    target_type = _as_str(dispute.get("target_type") or dispute.get("kind") or "").strip().lower()
    target_id = _as_str(dispute.get("target_id") or dispute.get("target") or "").strip().lower()
    if target_type in {"", "content", "post", "comment"}:
        return True
    return target_id.startswith("post:") or target_id.startswith("comment:")


def _active_assigned_reviewers(dispute: Json) -> list[str]:
    out: list[str] = []
    jurors = dispute.get("jurors")
    if isinstance(jurors, dict):
        for account_id, rec in jurors.items():
            if not _as_str(account_id).strip() or not isinstance(rec, dict):
                continue
            status = _as_str(rec.get("status") or "assigned").strip().lower() or "assigned"
            if status not in {"declined", "withdrawn", "timed_out", "removed", "replaced"}:
                out.append(_as_str(account_id).strip())
    assigned = dispute.get("assigned_jurors")
    if isinstance(assigned, list):
        for account_id in assigned:
            acct = _as_str(account_id).strip()
            if acct:
                out.append(acct)
    return sorted({acct for acct in out if acct})


def _content_review_assignment_candidates(state: Json, dispute: Json) -> list[str]:
    owner = _content_target_owner_for_assignment(state, dispute)
    out: list[str] = []
    seen: set[str] = set()
    for raw in eligible_reviewer_ids(state, CONTENT_REVIEW_LANE):
        acct = _resolve_account_identity(state, raw)
        if not acct or acct in seen:
            continue
        if owner and _same_account(owner, acct):
            continue
        seen.add(acct)
        out.append(acct)
    return sorted(out)


def schedule_content_review_assignment_system_txs(state: Json, *, next_height: int, phase: str) -> None:
    """Emit deterministic reviewer assignments for content reports that were left unassigned.

    Live two-node rehearsals can open a content report before every frontend has
    refreshed the latest reviewer-lane activation state.  The canonical fix is
    not a frontend-only fallback: each post block deterministically scans public
    content-review disputes and emits DISPUTE_JUROR_ASSIGN for eligible,
    unconflicted content reviewers when no active assignment exists yet.  The
    target owner remains excluded, and the sorted eligible set keeps replay
    deterministic across nodes.
    """

    phase_n = _as_str(phase).strip().lower() or "post"
    if phase_n != "post":
        return
    disputes = state.get("disputes_by_id")
    if not isinstance(disputes, dict):
        return
    h = int(next_height)
    for dispute_id in sorted(str(k) for k in disputes.keys()):
        dispute = disputes.get(dispute_id)
        if not isinstance(dispute, dict) or not _is_content_review_dispute(dispute):
            continue
        stage = _as_str(dispute.get("stage") or "").strip().lower()
        if stage not in {"", "open", "unassigned", "juror_review"}:
            continue
        if _active_assigned_reviewers(dispute):
            continue
        blocked = _as_str(dispute.get("assignment_blocked_reason") or "").strip().lower()
        if blocked and blocked not in {"no_unconflicted_content_reviewer", "reviewer_state_pending"}:
            continue
        candidates = _content_review_assignment_candidates(state, dispute)
        if not candidates:
            continue
        for reviewer in candidates:
            enqueue_system_tx(
                state,
                tx_type="DISPUTE_JUROR_ASSIGN",
                payload={
                    "dispute_id": dispute_id,
                    "juror": reviewer,
                    "assignment_source": "content_review_assignment_scheduler",
                },
                due_height=h,
                signer="SYSTEM",
                once=True,
                parent="CONTENT_ESCALATE_TO_DISPUTE",
                phase="post",
            )

def system_tx_emitter(
    state: Json,
    canon: Any,
    *,
    next_height: int,
    phase: str,
    proposer: str = "",
) -> list[TxEnvelope]:
    out: list[TxEnvelope] = []

    # Leader-only scheduling: enqueue deterministic system txs that must be
    # included in the block. Followers replay the block and do not call this.
    try:
        schedule_block_rewards_system_txs(
            state, next_height=int(next_height), proposer=str(proposer or ""), phase=phase
        )
    except Exception as exc:
        raise SystemSchedulerError(f"block_rewards_schedule_failed:{type(exc).__name__}") from exc

    try:
        schedule_content_review_assignment_system_txs(state, next_height=int(next_height), phase=phase)
    except Exception as exc:
        raise SystemSchedulerError(f"content_review_assignment_schedule_failed:{type(exc).__name__}") from exc

    items = _select_due_items_with_indexes(state, next_height=int(next_height), phase=phase)
    ledger = state
    queue_root = _queue_root(state)

    for queue_idx, it in items:
        # Internal queue emits system envelopes.
        _ = _is_system_only(canon, it.tx_type)
        _ = _canon_context(canon, it.tx_type)

        payload = dict(it.payload or {})
        payload.setdefault("_due_height", int(it.due_height))
        payload.setdefault("_system_queue_id", it.queue_id)

        signer = it.signer or "SYSTEM"
        if str(signer).strip() == "SYSTEM":
            params = ledger.get("params")
            if isinstance(params, dict):
                override = str(params.get("system_signer") or "").strip()
                if override:
                    signer = override

        # IMPORTANT: treat missing _parent_ref as "" (not "None")
        payload_parent_ref = _as_opt_str(payload.get("_parent_ref")).strip()

        # Prefer explicit queue parent, then payload ref
        parent_ref = it.parent.strip() if it.parent else payload_parent_ref

        # Receipt-only means it can only be emitted on the system/block path,
        # but it does *not* necessarily imply a parent reference is required.
        # Parent requirements are tracked separately in canon.
        parent_required = _canon_parent_required(canon, it.tx_type)

        # Autofill parent_ref from canon *only* when canon explicitly requires it.
        if parent_required and not parent_ref:
            parent_ref = parent_required

        # If canon requires a parent and we still do not have one, skip emission
        # rather than emitting an invalid receipt envelope.
        if parent_required and not parent_ref:
            continue

        # Keep payload consistent with envelope (helps downstream apply paths)
        if parent_ref:
            payload.setdefault("_parent_ref", parent_ref)

        out.append(
            TxEnvelope(
                tx_type=it.tx_type,
                signer=signer,
                nonce=0,
                payload=payload,
                sig="",
                parent=parent_ref if parent_ref else None,
                system=True,
            )
        )

        if it.once:
            if (
                0 <= int(queue_idx) < len(queue_root)
                and isinstance(queue_root[int(queue_idx)], dict)
                and _as_str(queue_root[int(queue_idx)].get("queue_id")).strip() == it.queue_id
            ):
                queue_root[int(queue_idx)]["emitted_height"] = int(next_height)
            else:
                confirm_system_tx_emitted(state, queue_id=it.queue_id, emitted_height=int(next_height))

    return out



def _system_payload_hash(payload: Json) -> str:
    raw = json.dumps(payload if isinstance(payload, dict) else {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _expected_emitted_system_env_fields(state: Json, canon: Any, item: SystemQueueItem) -> tuple[Json, str, str]:
    payload = dict(item.payload or {})
    payload.setdefault("_due_height", int(item.due_height))
    payload.setdefault("_system_queue_id", item.queue_id)

    signer = item.signer or "SYSTEM"
    if str(signer).strip() == "SYSTEM":
        params = state.get("params")
        if isinstance(params, dict):
            override = str(params.get("system_signer") or "").strip()
            if override:
                signer = override

    payload_parent_ref = _as_opt_str(payload.get("_parent_ref")).strip()
    parent_ref = item.parent.strip() if item.parent else payload_parent_ref
    parent_required = _canon_parent_required(canon, item.tx_type)
    if parent_required and not parent_ref:
        parent_ref = parent_required
    if parent_ref:
        payload.setdefault("_parent_ref", parent_ref)
    return payload, str(signer or "SYSTEM"), parent_ref if parent_ref else ""


def validate_system_tx_queue_binding(
    state: Json,
    canon: Any,
    env: TxEnvelope,
    *,
    next_height: int,
    phase: str,
    queue_objects_by_id: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    """Validate that a block SYSTEM tx came from deterministic system_queue output."""
    if not bool(getattr(env, "system", False)):
        return True, ""
    payload = env.payload if isinstance(env.payload, dict) else {}
    qid = _as_str(payload.get("_system_queue_id") or "").strip()
    if not qid:
        return False, "missing_system_queue_id"
    phase_n = _as_str(phase).strip().lower() or "post"
    found: SystemQueueItem | None = _lookup_queue_item(queue_objects_by_id, qid)
    if found is None:
        for item in _validated_queue_items(state):
            if item.queue_id == qid:
                found = item
                break
    if found is None:
        return False, "unknown_system_queue_id"
    tx_type = _as_str(getattr(env, "tx_type", "") or "").strip().upper()
    if found.tx_type != tx_type:
        return False, "system_queue_tx_type_mismatch"
    if int(found.due_height) != int(next_height):
        return False, "system_queue_due_height_mismatch"
    if int(payload.get("_due_height") or 0) != int(next_height):
        return False, "system_payload_due_height_mismatch"
    if found.phase != phase_n:
        return False, "system_queue_phase_mismatch"
    expected_payload, expected_signer, expected_parent = _expected_emitted_system_env_fields(state, canon, found)
    signer = _as_str(getattr(env, "signer", "") or "").strip()
    if signer != expected_signer:
        return False, "system_queue_signer_mismatch"
    parent = _as_opt_str(getattr(env, "parent", None)).strip()
    if parent != expected_parent:
        return False, "system_queue_parent_mismatch"
    if _system_payload_hash(payload) != _system_payload_hash(expected_payload):
        return False, "system_queue_payload_mismatch"
    emitted_height = found.emitted_height
    if emitted_height is not None and int(emitted_height) not in {0, int(next_height)}:
        return False, "system_queue_emitted_height_mismatch"
    return True, ""

def confirm_system_tx_emitted(state: Json, *, queue_id: str, emitted_height: int) -> bool:
    qid = _as_str(queue_id).strip()
    if not qid:
        return False
    root = _queue_root(state)
    found = False
    for idx, item in enumerate(_validated_queue_items(state)):
        if item.queue_id == qid:
            root[idx]["emitted_height"] = int(emitted_height)
            found = True
            break
    return found


def prune_emitted_system_queue(state: Json) -> int:
    items = _validated_queue_items(state)
    before = len(items)
    kept: list[Json] = []
    for item in items:
        if item.once and isinstance(item.emitted_height, int):
            continue
        kept.append(item.to_ledger_obj())
    state["system_queue"] = kept
    return before - len(kept)


__all__ = [
    "SystemQueueCorruptionError",
    "SystemSchedulerError",
    "SystemTxEngineError",
    "SystemQueueItem",
    "build_system_queue_lookup",
    "confirm_system_tx_emitted",
    "enqueue_system_tx",
    "prune_emitted_system_queue",
    "system_queue_phase_for_id",
    "schedule_block_rewards_system_txs",
    "schedule_content_review_assignment_system_txs",
    "system_tx_emitter",
    "validate_system_tx_queue_binding",
]
