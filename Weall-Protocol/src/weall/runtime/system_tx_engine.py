# src/weall/runtime/system_tx_engine.py
from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

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
from weall.runtime.bounded_rollback import (
    journal_append_list,
    journal_set_dict_key,
    materialize_journaled,
)
from weall.runtime.econ_phase import econ_allowed_from_state
from weall.runtime.lineage_witness import (
    LineageWitness,
    LineageWitnessKind,
    make_single_tx_witness,
    validate_lineage_witness,
)
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import TxIndex

Json = dict[str, Any]

LINEAGE_WITNESS_PAYLOAD_KEY = "_lineage_witness"
BLOCK_FINALIZE_TX_TYPE = "BLOCK_FINALIZE"
EPOCH_FINALITY_SINGLE_TX_CHILDREN = frozenset({"EPOCH_OPEN", "EPOCH_CLOSE"})


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
    if not isinstance(info, dict):
        return False
    # Canon marks receipt/system-envelope transactions with origin=SYSTEM.
    # Some generated projections do not materialize a separate system_only flag,
    # so treating absence of that projection-only field as non-system corrupts
    # valid governance/system queue entries. Preserve an explicit system_only
    # marker when present, otherwise use the authoritative origin classification.
    if info.get("system_only") is True:
        return True
    return str(info.get("origin") or "").strip().upper() == "SYSTEM"


def _is_receipt_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    return bool(info.get("receipt_only") is True) if isinstance(info, dict) else False


def _canon_parent_tx_type(canon: Any, tx_type: str) -> str:
    info = _canon_info(canon, tx_type)
    if not isinstance(info, dict):
        return ""
    return _as_str(info.get("parent_tx_type") or "").strip().upper()


def _single_tx_lineage_shape(
    canon: Any,
    env: TxEnvelope,
    *,
    required_child_tx_types: Collection[str],
) -> tuple[bool, str, LineageWitness | None]:
    tx_type = _as_str(getattr(env, "tx_type", "") or "").strip().upper()
    required = {_as_str(value).strip().upper() for value in required_child_tx_types}
    if tx_type not in required:
        return True, "", None

    expected_parent = _canon_parent_tx_type(canon, tx_type)
    if not expected_parent:
        return False, "lineage_parent_tx_type_missing", None

    payload = env.payload if isinstance(env.payload, dict) else {}
    raw = payload.get(LINEAGE_WITNESS_PAYLOAD_KEY)
    if not isinstance(raw, Mapping):
        return False, "lineage_witness_missing", None

    verdict = validate_lineage_witness(raw, expected_parent_tx_type=expected_parent)
    if not verdict.ok or verdict.witness is None:
        return False, f"lineage_witness_invalid:{verdict.reason}", None
    witness = verdict.witness
    if witness.kind is not LineageWitnessKind.SINGLE_TX:
        return False, "lineage_witness_kind_mismatch", None
    if witness.same_block_position is None:
        return False, "lineage_same_block_position_missing", None
    if witness.scope:
        return False, "lineage_same_block_scope_must_be_empty", None
    return True, "", witness


def validate_same_block_single_tx_lineage(
    canon: Any,
    env: TxEnvelope,
    *,
    prior_txs: Sequence[Mapping[str, Any]],
    required_child_tx_types: Collection[str],
) -> tuple[bool, str]:
    """Verify an enforced SINGLE_TX witness against an earlier block transaction."""

    ok, reason, witness = _single_tx_lineage_shape(
        canon, env, required_child_tx_types=required_child_tx_types
    )
    if not ok or witness is None:
        return ok, reason

    position = int(witness.same_block_position)
    if position < 0 or position >= len(prior_txs):
        return False, "lineage_parent_position_not_prior"
    parent = prior_txs[position]
    if not isinstance(parent, Mapping):
        return False, "lineage_parent_not_object"

    parent_tx_id = _as_str(parent.get("tx_id") or "").strip()
    if parent_tx_id != witness.parent_tx_id:
        return False, "lineage_parent_tx_id_mismatch"
    parent_tx_type = _as_str(parent.get("tx_type") or "").strip().upper()
    if parent_tx_type != witness.parent_tx_type:
        return False, "lineage_parent_tx_type_mismatch"
    return True, ""


def bind_new_same_block_single_tx_children(
    state: Json,
    canon: Any,
    *,
    queue_ids_before: Collection[str],
    parent_tx_type: str,
    parent_tx_id: str,
    parent_position: int,
    child_tx_types: Collection[str],
) -> int:
    """Bind newly queued exact children to the concrete parent transaction instance.

    This is intentionally narrow: only queue entries appended by the just-applied
    parent transaction and explicitly named by ``child_tx_types`` are eligible.
    Existing/delayed queue entries are never rebound by a global latest-by-type
    lookup.  The legacy ``parent`` context reference remains untouched.
    """

    parent_type = _as_str(parent_tx_type).strip().upper()
    parent_id = _as_str(parent_tx_id).strip()
    if not parent_type:
        raise SystemQueueCorruptionError("single_tx_lineage_parent_type_required")
    parent_witness = make_single_tx_witness(
        parent_tx_type=parent_type,
        parent_tx_id=parent_id,
        same_block_position=int(parent_position),
    ).to_json()

    before = {_as_str(value).strip() for value in queue_ids_before if _as_str(value).strip()}
    children = {_as_str(value).strip().upper() for value in child_tx_types}
    root = _queue_root(state)
    items = _validated_queue_items_from_root(root)
    known_ids = {item.queue_id for _idx, item in items}
    rebound = 0

    for idx, item in items:
        if item.queue_id in before or item.tx_type not in children:
            continue
        expected_parent = _canon_parent_tx_type(canon, item.tx_type)
        if expected_parent != parent_type:
            raise SystemQueueCorruptionError(
                "single_tx_lineage_parent_type_mismatch:"
                f"{item.tx_type}:{expected_parent}:{parent_type}"
            )
        payload = dict(item.payload or {})
        if LINEAGE_WITNESS_PAYLOAD_KEY in payload:
            raise SystemQueueCorruptionError(
                f"single_tx_lineage_witness_already_present:{item.tx_type}"
            )
        payload[LINEAGE_WITNESS_PAYLOAD_KEY] = dict(parent_witness)
        new_qid = _queue_id_for_fields(
            tx_type=item.tx_type,
            payload=payload,
            signer=item.signer,
            due_height=item.due_height,
            parent=item.parent,
            phase=item.phase,
            once=item.once,
        )
        if new_qid != item.queue_id and new_qid in known_ids:
            raise SystemQueueCorruptionError(
                f"single_tx_lineage_queue_id_collision:{item.tx_type}:{new_qid}"
            )
        known_ids.discard(item.queue_id)
        known_ids.add(new_qid)
        root[idx]["payload"] = payload
        root[idx]["queue_id"] = new_qid
        rebound += 1

    return rebound


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
    if root is None:
        root = []
        journal_set_dict_key(state, "system_queue", root, "system_queue")
    elif not isinstance(root, list):
        raise SystemQueueCorruptionError("system_queue_not_list")
    return root


def _validated_queue_items_from_root(root: list[Any]) -> list[tuple[int, SystemQueueItem]]:
    items: list[tuple[int, SystemQueueItem]] = []
    seen_queue_ids: set[str] = set()
    for idx, obj in enumerate(root):
        if not isinstance(obj, dict):
            raise SystemQueueCorruptionError(f"system_queue_item_not_object:{idx}")
        if not isinstance(obj.get("payload"), dict):
            raise SystemQueueCorruptionError(f"system_queue_item_payload_not_object:{idx}")
        if not isinstance(obj.get("once", True), bool):
            raise SystemQueueCorruptionError(f"system_queue_item_once_not_bool:{idx}")
        raw_due = obj.get("due_height")
        if not isinstance(raw_due, int) or isinstance(raw_due, bool):
            raise SystemQueueCorruptionError(f"system_queue_item_bad_due_height:{idx}")
        raw_emitted = obj.get("emitted_height")
        if raw_emitted is not None and (
            not isinstance(raw_emitted, int) or isinstance(raw_emitted, bool)
        ):
            raise SystemQueueCorruptionError(f"system_queue_item_bad_emitted_height:{idx}")
        try:
            item = SystemQueueItem.from_ledger_obj(obj)
        except (TypeError, ValueError) as exc:
            raise SystemQueueCorruptionError(f"system_queue_item_invalid:{idx}") from exc

        if not item.queue_id:
            raise SystemQueueCorruptionError(f"system_queue_item_missing_queue_id:{idx}")
        if not item.tx_type:
            raise SystemQueueCorruptionError(f"system_queue_item_missing_tx_type:{idx}")
        if int(item.due_height) <= 0:
            raise SystemQueueCorruptionError(f"system_queue_item_bad_due_height:{idx}")
        if item.phase not in {"pre", "post"}:
            raise SystemQueueCorruptionError(f"system_queue_item_bad_phase:{idx}")
        expected_qid = _queue_id_for_fields(
            tx_type=item.tx_type,
            payload=item.payload,
            signer=item.signer,
            due_height=item.due_height,
            parent=item.parent,
            phase=item.phase,
            once=item.once,
        )
        if item.queue_id != expected_qid:
            raise SystemQueueCorruptionError(f"system_queue_item_queue_id_mismatch:{idx}")
        if item.queue_id in seen_queue_ids:
            raise SystemQueueCorruptionError(f"system_queue_duplicate_queue_id:{item.queue_id}")
        seen_queue_ids.add(item.queue_id)
        if item.emitted_height is not None:
            if not item.once or int(item.emitted_height) != int(item.due_height):
                raise SystemQueueCorruptionError(f"system_queue_item_bad_emitted_height:{idx}")
        items.append((idx, item))
    return items


def _validated_queue_items_with_indexes(state: Json) -> list[tuple[int, SystemQueueItem]]:
    return _validated_queue_items_from_root(_queue_root(state))


def _validated_queue_items(state: Json) -> list[SystemQueueItem]:
    return [item for _idx, item in _validated_queue_items_with_indexes(state)]


def validate_system_queue_recovery_state(
    state: Json, *, committed_height: int | None = None
) -> None:
    """Validate persisted/imported SYSTEM queue state at a committed height.

    Recovery boundaries must reject canonical state that cannot make forward
    progress. Any un-emitted queue item whose due height is already at or below
    the committed state height is permanently unselectable by the next block and
    therefore represents corrupt canonical state. This helper is read-only.
    """

    height_raw = state.get("height") if committed_height is None else committed_height
    if not isinstance(height_raw, int) or isinstance(height_raw, bool):
        raise SystemQueueCorruptionError("system_queue_recovery_bad_committed_height")
    height = int(height_raw)
    if height < 0:
        raise SystemQueueCorruptionError("system_queue_recovery_bad_committed_height")

    root_any = state.get("system_queue")
    if root_any is None:
        return
    if not isinstance(root_any, list):
        raise SystemQueueCorruptionError("system_queue_not_list")

    for _idx, item in _validated_queue_items_from_root(root_any):
        if item.once and item.emitted_height is not None:
            continue
        if int(item.due_height) <= height:
            raise SystemQueueCorruptionError(
                f"system_queue_item_past_due_at_recovery:{item.queue_id}:"
                f"{int(item.due_height)}:{height}"
            )


def build_system_queue_lookup(state: Json) -> dict[str, Json]:
    """Return a first-match queue-id lookup without mutating replicated state.

    Missing queue state is equivalent to an empty queue for legacy snapshots. A
    present non-list value is corruption and must fail closed; validation must
    never "repair" canonical state merely by reading it. Returned values remain
    the live ledger dictionaries so later binding checks observe emitter updates.
    """
    root_any = state.get("system_queue")
    if root_any is None:
        return {}
    if not isinstance(root_any, list):
        raise SystemQueueCorruptionError("system_queue_not_list")

    lookup: dict[str, Json] = {}
    for idx, item in _validated_queue_items_from_root(root_any):
        obj = root_any[idx]
        if not isinstance(obj, dict):
            raise SystemQueueCorruptionError(f"system_queue_item_not_object:{idx}")
        lookup[item.queue_id] = obj
    return lookup


def _lookup_queue_item(
    queue_objects_by_id: Mapping[str, Any] | None, qid: str
) -> SystemQueueItem | None:
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
    return {item.queue_id for item in _validated_queue_items(state)}


def _queue_id_for_fields(
    *,
    tx_type: str,
    payload: Json,
    signer: str,
    due_height: int,
    parent: str,
    phase: str,
    once: bool,
) -> str:
    raw_payload = materialize_journaled(payload)
    if not isinstance(raw_payload, dict):
        raise ValueError("system_queue_payload_not_object")
    base = {
        "tx_type": _as_str(tx_type).strip().upper(),
        "payload": raw_payload,
        "signer": _as_str(signer).strip() or "SYSTEM",
        "due_height": int(due_height),
        "parent": _as_opt_str(parent).strip(),
        "phase": _as_str(phase).strip().lower() or "post",
        "once": bool(once),
    }
    raw = json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


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
    if not tx_type_u:
        raise ValueError("system_queue_tx_type_required")
    if phase_n not in {"pre", "post"}:
        raise ValueError("system_queue_phase_invalid")
    if int(due_height) <= 0:
        raise ValueError("system_queue_due_height_invalid")
    if not isinstance(payload, dict):
        raise ValueError("system_queue_payload_not_object")

    raw_payload = materialize_journaled(payload)
    if not isinstance(raw_payload, dict):
        raise ValueError("system_queue_payload_not_object")
    base = {
        "tx_type": tx_type_u,
        "payload": raw_payload,
        "signer": _as_str(signer).strip() or "SYSTEM",
        "due_height": int(due_height),
        "parent": parent_norm,
        "phase": phase_n,
        "once": bool(once),
    }

    qid = _queue_id_for_fields(**base)
    base["queue_id"] = qid

    if qid in _queue_ids(state):
        return qid

    journal_append_list(_queue_root(state), base, "system_queue")
    return qid


def _select_due_items_with_indexes(
    state: Json, *, next_height: int, phase: str
) -> list[tuple[int, SystemQueueItem]]:
    out: list[tuple[int, SystemQueueItem]] = []
    phase_n = _as_str(phase).strip().lower() or "post"
    for idx, item in _validated_queue_items_with_indexes(state):
        if item.emitted_height is not None and item.once:
            continue
        if int(item.due_height) < int(next_height):
            raise SystemQueueCorruptionError(
                f"system_queue_item_past_due:{item.queue_id}:{int(item.due_height)}:{int(next_height)}"
            )
        if item.phase != phase_n:
            continue
        if int(item.due_height) != int(next_height):
            continue

        out.append((idx, item))
    return out


def _select_due_items(state: Json, *, next_height: int, phase: str) -> list[SystemQueueItem]:
    return [
        item
        for _idx, item in _select_due_items_with_indexes(
            state, next_height=next_height, phase=phase
        )
    ]


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

    items = _select_due_items_with_indexes(state, next_height=int(next_height), phase=phase)
    ledger = state
    queue_root = _queue_root(state)

    for queue_idx, it in items:
        # Internal queue is a production authority boundary. When canon metadata
        # is supplied, validate every emitted envelope against its authoritative
        # SYSTEM/block classification. Some deterministic unit/replay callers
        # intentionally omit canon; those still pass through the queue's lineage
        # and authenticated system-envelope checks below rather than being
        # rejected solely because classification metadata was unavailable.
        if canon is not None:
            if not _is_system_only(canon, it.tx_type):
                raise SystemQueueCorruptionError(f"system_queue_non_system_tx:{it.tx_type}")
            if _canon_context(canon, it.tx_type) != "block":
                raise SystemQueueCorruptionError(f"system_queue_non_block_context:{it.tx_type}")

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

        # Canon parent metadata names a parent TxType, while ``parent_ref`` is a
        # concrete transaction/context reference supplied by the scheduler. Never
        # synthesize an instance reference from the TxType name.

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
                confirm_system_tx_emitted(
                    state, queue_id=it.queue_id, emitted_height=int(next_height)
                )

    return out


def _system_payload_hash(payload: Json) -> str:
    raw = json.dumps(
        payload if isinstance(payload, dict) else {}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _expected_emitted_system_env_fields(
    state: Json, canon: Any, item: SystemQueueItem
) -> tuple[Json, str, str]:
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
    if parent_ref:
        payload.setdefault("_parent_ref", parent_ref)
    return payload, str(signer or "SYSTEM"), parent_ref if parent_ref else ""


def _declared_parent_tx_types(canon: TxIndex, tx_type: str) -> tuple[str, ...]:
    info = _canon_info(canon, tx_type)
    if not isinstance(info, dict):
        return ()
    raw = info.get("parent_tx_types")
    if isinstance(raw, list):
        vals = tuple(str(x).strip().upper() for x in raw if str(x).strip())
        if vals:
            return vals
    one = str(info.get("parent_tx_type") or "").strip().upper()
    return (one,) if one else ()


def _strict_receipt_lineage_required(state: Json) -> bool:
    params = state.get("params")
    if not isinstance(params, dict):
        return False
    return bool(params.get("strict_civic_governance_enabled")) or bool(
        params.get("validator_candidate_lifecycle_gate_enabled")
    )


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
    if _strict_receipt_lineage_required(state) and _is_receipt_only(canon, tx_type):
        allowed_parents = _declared_parent_tx_types(canon, tx_type)
        if allowed_parents:
            raw_witness = payload.get("_lineage_witness")
            if not isinstance(raw_witness, dict):
                return False, "lineage_witness_required"
            verdict0 = validate_lineage_witness(raw_witness)
            if not verdict0.ok or verdict0.witness is None:
                return False, f"lineage_witness_invalid:{verdict0.reason}"
            witness0 = verdict0.witness
            if witness0.parent_tx_type not in allowed_parents:
                return False, "lineage_parent_tx_type_not_declared"
            if witness0.kind is LineageWitnessKind.SINGLE_TX:
                parent0 = _as_opt_str(getattr(env, "parent", None)).strip()
                if not parent0 or witness0.parent_tx_id != parent0:
                    return False, "lineage_parent_tx_id_mismatch"
    lineage_ok, lineage_reason, _ = _single_tx_lineage_shape(
        canon,
        env,
        required_child_tx_types=EPOCH_FINALITY_SINGLE_TX_CHILDREN,
    )
    if not lineage_ok:
        return False, lineage_reason
    if int(found.due_height) != int(next_height):
        return False, "system_queue_due_height_mismatch"
    if int(payload.get("_due_height") or 0) != int(next_height):
        return False, "system_payload_due_height_mismatch"
    if found.phase != phase_n:
        return False, "system_queue_phase_mismatch"
    expected_payload, expected_signer, expected_parent = _expected_emitted_system_env_fields(
        state, canon, found
    )
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
    "BLOCK_FINALIZE_TX_TYPE",
    "EPOCH_FINALITY_SINGLE_TX_CHILDREN",
    "LINEAGE_WITNESS_PAYLOAD_KEY",
    "bind_new_same_block_single_tx_children",
    "build_system_queue_lookup",
    "confirm_system_tx_emitted",
    "enqueue_system_tx",
    "prune_emitted_system_queue",
    "system_queue_phase_for_id",
    "schedule_block_rewards_system_txs",
    "system_tx_emitter",
    "validate_same_block_single_tx_lineage",
    "validate_system_tx_queue_binding",
]
