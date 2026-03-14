# src/weall/runtime/system_tx_engine.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import TxIndex

# Rewards scheduling (Genesis v2.1): leaders enqueue deterministic reward system txs
# inside the block. Followers never run the scheduler; they replay the included txs.
from weall.ledger.constants import MAX_SUPPLY, MINT_POOL_ACCOUNT_ID, TREASURY_ACCOUNT_ID
from weall.ledger.roles_schema import ensure_roles_schema
from weall.ledger.rewards import block_subsidy
from weall.runtime.econ_phase import econ_allowed_from_state

Json = Dict[str, Any]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return ""


def _as_opt_str(v: Any) -> str:
    """Like _as_str, but treats None as empty string (critical for parent refs)."""
    if v is None:
        return ""
    return _as_str(v)


def _canon_info(canon: Any, tx_type: str) -> Optional[Dict[str, Any]]:
    """Return canon entry for tx_type, supporting both TxIndex and lightweight dict stubs.

    TxIndex: canon.get(tx_type) -> dict|None
    Dict stub (tests): {"by_name": {tx_type: {...}}}
    Dict fallback: {tx_type: {...}}
    """
    tx_u = _as_str(tx_type).strip().upper()
    if not tx_u:
        return None

    try:
        if isinstance(canon, TxIndex):
            info = canon.get(tx_u)
            return info if isinstance(info, dict) else None
    except Exception:
        pass

    if isinstance(canon, dict):
        by_name = canon.get("by_name")
        if isinstance(by_name, dict):
            info = by_name.get(tx_u)
            return info if isinstance(info, dict) else None

        info = canon.get(tx_u)
        return info if isinstance(info, dict) else None

    try:
        info = canon.get(tx_u)  # type: ignore[attr-defined]
        return info if isinstance(info, dict) else None
    except Exception:
        return None


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


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _uniq_strs(xs: List[Any]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for it in xs:
        s = _as_str(it).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _reward_recipients(state: Json, proposer: str) -> Dict[str, List[str]]:
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


def _even_split(amount: int, recipients: List[str]) -> tuple[Dict[str, int], int]:
    amt = int(amount)
    recips = [r for r in recipients if isinstance(r, str) and r.strip()]
    if amt <= 0 or not recips:
        return {}, amt
    n = len(recips)
    share = amt // n
    if share <= 0:
        return {}, amt
    payouts: Dict[str, int] = {}
    for r in recips:
        payouts[r] = payouts.get(r, 0) + share
    remainder = amt - (share * n)
    return payouts, remainder


def _monetary_policy_snapshot(state: Json) -> Dict[str, int]:
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
    """Enqueue Genesis block reward system txs.

    Gate:
      - During the Genesis economic lock OR when economics are disabled, rewards are not emitted.

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

    reward_block_id = f"height:{h}"

    mp = _monetary_policy_snapshot(state)
    issued = int(mp.get("issued", 0))

    raw_subsidy = int(block_subsidy(h))
    if issued >= int(MAX_SUPPLY):
        subsidy = 0
    else:
        remaining = int(MAX_SUPPLY) - int(issued)
        subsidy = raw_subsidy if raw_subsidy <= remaining else remaining
        if subsidy < 0:
            subsidy = 0

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
    payouts: Dict[str, int] = {}
    treasury_extra = 0

    for bucket_name in ("validators", "operators", "jurors", "creators"):
        amt = int(buckets.get(bucket_name, 0))
        rs = recips.get(bucket_name, [])
        sub_payouts, rem = _even_split(amt, list(rs))
        treasury_extra += int(rem)
        for acct_id, a in sub_payouts.items():
            payouts[acct_id] = payouts.get(acct_id, 0) + int(a)

    payouts[TREASURY_ACCOUNT_ID] = payouts.get(TREASURY_ACCOUNT_ID, 0) + int(buckets.get("treasury", 0)) + int(
        treasury_extra
    )

    transfers: List[Json] = []
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
    debits: List[Json] = []
    if total_reward > 0:
        debits.append({"from": MINT_POOL_ACCOUNT_ID, "amount": int(total_reward)})

    enqueue_system_tx(
        state,
        tx_type="BLOCK_REWARD_MINT",
        payload={
            "block_id": reward_block_id,
            "height": h,
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
    emitted_height: Optional[int] = None

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
    def from_ledger_obj(obj: Any) -> "SystemQueueItem":
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
            emitted_height=obj.get("emitted_height") if isinstance(obj.get("emitted_height"), int) else None,
        )


def _queue_root(state: Json) -> List[Json]:
    root = state.get("system_queue")
    if not isinstance(root, list):
        root = []
        state["system_queue"] = root
    return root


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
    parent: Optional[str] = None,
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

    _queue_root(state).append(base)
    return qid


def _select_due_items(state: Json, *, next_height: int, phase: str) -> List[SystemQueueItem]:
    out: List[SystemQueueItem] = []
    phase_n = _as_str(phase).strip().lower() or "post"
    for obj in _queue_root(state):
        if not isinstance(obj, dict):
            continue
        try:
            item = SystemQueueItem.from_ledger_obj(obj)
        except Exception:
            continue

        if item.emitted_height is not None and item.once:
            continue
        if item.phase != phase_n:
            continue
        if int(item.due_height) != int(next_height):
            continue

        out.append(item)
    return out


def system_tx_emitter(
    state: Json,
    canon: Any,
    *,
    next_height: int,
    phase: str,
    proposer: str = "",
) -> List[TxEnvelope]:
    out: List[TxEnvelope] = []

    # Leader-only scheduling: enqueue deterministic system txs that must be
    # included in the block. Followers replay the block and do not call this.
    try:
        schedule_block_rewards_system_txs(state, next_height=int(next_height), proposer=str(proposer or ""), phase=phase)
    except Exception:
        # Never crash block production because of a scheduler bug; fail-closed
        # behavior for economic actions is enforced in apply modules.
        pass

    items = _select_due_items(state, next_height=int(next_height), phase=phase)
    ledger = state

    for it in items:
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
        is_receipt = _is_receipt_only(canon, it.tx_type)
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
            confirm_system_tx_emitted(state, queue_id=it.queue_id, emitted_height=int(next_height))

    return out


def confirm_system_tx_emitted(state: Json, *, queue_id: str, emitted_height: int) -> bool:
    qid = _as_str(queue_id).strip()
    if not qid:
        return False
    for obj in _queue_root(state):
        if not isinstance(obj, dict):
            continue
        if _as_str(obj.get("queue_id")).strip() == qid:
            obj["emitted_height"] = int(emitted_height)
            return True
    return False


def prune_emitted_system_queue(state: Json) -> int:
    root = _queue_root(state)
    before = len(root)
    kept: List[Json] = []
    for obj in root:
        if not isinstance(obj, dict):
            continue
        once = bool(obj.get("once", True))
        eh = obj.get("emitted_height")
        if once and isinstance(eh, int):
            continue
        kept.append(obj)
    state["system_queue"] = kept
    return before - len(kept)
