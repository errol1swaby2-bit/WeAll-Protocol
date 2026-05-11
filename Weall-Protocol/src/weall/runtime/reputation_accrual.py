from __future__ import annotations

"""Deterministic reputation accrual for verified public contributions.

Reputation is responsibility history, not a prerequisite for becoming human.
This scheduler only rewards Tier2 public contribution records after a maturity
window and emits SYSTEM-only REPUTATION_DELTA_APPLY transactions.
"""

from typing import Any

from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]

DEFAULT_CONTENT_REPUTATION_MATURITY_BLOCKS = 8
DEFAULT_POST_REPUTATION_DELTA_MILLI = 10
DEFAULT_MEDIA_REPUTATION_DELTA_MILLI = 25


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _params(state: Json) -> Json:
    return _as_dict(state.get("params"))


def content_reputation_maturity_blocks(state: Json) -> int:
    params = _params(state)
    raw = params.get("content_reputation_maturity_blocks")
    if raw is None:
        raw = _as_dict(params.get("reputation")).get("content_maturity_blocks")
    return max(1, _as_int(raw, DEFAULT_CONTENT_REPUTATION_MATURITY_BLOCKS))


def post_reputation_delta_milli(state: Json) -> int:
    params = _params(state)
    raw = params.get("post_reputation_delta_milli")
    if raw is None:
        raw = _as_dict(params.get("reputation")).get("post_delta_milli")
    return max(0, _as_int(raw, DEFAULT_POST_REPUTATION_DELTA_MILLI))


def media_reputation_delta_milli(state: Json) -> int:
    params = _params(state)
    raw = params.get("media_reputation_delta_milli")
    if raw is None:
        raw = _as_dict(params.get("reputation")).get("media_delta_milli")
    return max(0, _as_int(raw, DEFAULT_MEDIA_REPUTATION_DELTA_MILLI))


def pending_content_accrual(
    *,
    kind: str,
    source_id: str,
    account_id: str,
    created_height: int,
    delta_milli: int,
    maturity_blocks: int,
) -> Json:
    return {
        "kind": str(kind),
        "source_id": str(source_id),
        "account_id": str(account_id),
        "created_height": int(created_height),
        "matures_at_height": int(created_height) + int(maturity_blocks),
        "delta_milli": int(delta_milli),
        "status": "pending",
    }


def _flag_targets(content: Json) -> set[str]:
    flags = content.get("flags")
    if not isinstance(flags, dict):
        return set()
    out: set[str] = set()
    for rec_any in flags.values():
        rec = _as_dict(rec_any)
        target = _as_str(rec.get("target_id") or rec.get("post_id") or rec.get("media_id")).strip()
        if target:
            out.add(target)
    return out


def _post_clean(rec: Json, source_id: str, flagged: set[str]) -> bool:
    if bool(rec.get("deleted", False)):
        return False
    visibility = _as_str(rec.get("visibility") or "public").strip().lower() or "public"
    if visibility != "public":
        return False
    if source_id in flagged:
        return False
    embedded_flags = rec.get("flags")
    if isinstance(embedded_flags, list) and embedded_flags:
        return False
    return True


def _media_clean(rec: Json, source_id: str, flagged: set[str]) -> bool:
    if source_id in flagged:
        return False
    if bool(rec.get("deleted", False)):
        return False
    cid = _as_str(rec.get("cid") or rec.get("ipfs_cid") or rec.get("content_cid")).strip()
    return bool(cid)


def _enqueue_accrual(
    state: Json,
    *,
    accrual: Json,
    next_height: int,
    reason: str,
) -> bool:
    account_id = _as_str(accrual.get("account_id")).strip()
    source_id = _as_str(accrual.get("source_id")).strip()
    kind = _as_str(accrual.get("kind")).strip()
    delta_milli = _as_int(accrual.get("delta_milli"), 0)
    if not account_id or not source_id or delta_milli <= 0:
        accrual["status"] = "ineligible"
        return False

    delta_id = f"repaccrual:{kind}:{source_id}"
    enqueue_system_tx(
        state,
        tx_type="REPUTATION_DELTA_APPLY",
        payload={
            "account_id": account_id,
            "delta": float(delta_milli) / 1000.0,
            "delta_id": delta_id,
            "reason": str(reason),
        },
        due_height=int(next_height),
        signer="SYSTEM",
        once=True,
        parent=delta_id,
        phase="post",
    )
    accrual["status"] = "queued"
    accrual["queued_height"] = int(next_height)
    accrual["delta_id"] = delta_id
    return True


def schedule_reputation_accrual_system_txs(state: Json, *, next_height: int) -> int:
    content = _as_dict(state.get("content"))
    if not content:
        return 0

    current_height = max(_as_int(state.get("height"), 0), int(next_height) - 1)
    flagged = _flag_targets(content)
    enqueued = 0

    posts = content.get("posts")
    if isinstance(posts, dict):
        for post_id, rec_any in sorted(posts.items()):
            rec = _as_dict(rec_any)
            accrual = _as_dict(rec.get("reputation_accrual"))
            if not accrual or _as_str(accrual.get("status")).strip().lower() != "pending":
                continue
            if current_height < _as_int(accrual.get("matures_at_height"), 0):
                continue
            sid = _as_str(accrual.get("source_id") or post_id).strip()
            if not _post_clean(rec, sid, flagged):
                accrual["status"] = "blocked"
                rec["reputation_accrual"] = accrual
                continue
            if _enqueue_accrual(
                state,
                accrual=accrual,
                next_height=next_height,
                reason="content_post_matured",
            ):
                enqueued += 1
            rec["reputation_accrual"] = accrual

    media = content.get("media")
    if isinstance(media, dict):
        for media_id, rec_any in sorted(media.items()):
            rec = _as_dict(rec_any)
            accrual = _as_dict(rec.get("reputation_accrual"))
            if not accrual or _as_str(accrual.get("status")).strip().lower() != "pending":
                continue
            if current_height < _as_int(accrual.get("matures_at_height"), 0):
                continue
            sid = _as_str(accrual.get("source_id") or media_id).strip()
            if not _media_clean(rec, sid, flagged):
                accrual["status"] = "blocked"
                rec["reputation_accrual"] = accrual
                continue
            if _enqueue_accrual(
                state,
                accrual=accrual,
                next_height=next_height,
                reason="content_media_matured",
            ):
                enqueued += 1
            rec["reputation_accrual"] = accrual

    return int(enqueued)


__all__ = [
    "DEFAULT_CONTENT_REPUTATION_MATURITY_BLOCKS",
    "DEFAULT_MEDIA_REPUTATION_DELTA_MILLI",
    "DEFAULT_POST_REPUTATION_DELTA_MILLI",
    "content_reputation_maturity_blocks",
    "media_reputation_delta_milli",
    "pending_content_accrual",
    "post_reputation_delta_milli",
    "schedule_reputation_accrual_system_txs",
]
