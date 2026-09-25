from __future__ import annotations

"""Legacy content-maturity reputation metadata.

Reputation is responsibility history, not a prerequisite for becoming human.

Historical builds attached a pending reputation accrual record to public posts
and media and later emitted ``REPUTATION_DELTA_APPLY`` when the record matured.
That emission path is not canonical: Tx Canon defines
``REPUTATION_DELTA_APPLY`` as a SYSTEM receipt whose parent is
``DISPUTE_RESOLVE``. Ordinary content maturity cannot satisfy that provenance
contract.

The helpers in this module remain temporarily so persisted state and callers
that still construct the legacy metadata can be handled deterministically. New
metadata is born retired, and the scheduler deterministically retires any
pre-existing pending records. It MUST NOT emit a reputation transaction.
Positive creator reputation belongs to the event-sourced Reputation Matrix and
must originate from a canonically supported evaluated contribution/outcome.
"""

from typing import Any

Json = dict[str, Any]

DEFAULT_CONTENT_REPUTATION_MATURITY_BLOCKS = 8
DEFAULT_POST_REPUTATION_DELTA_MILLI = 10
DEFAULT_MEDIA_REPUTATION_DELTA_MILLI = 25

RETIRED_CONTENT_ACCRUAL_STATUS = "retired_noncanonical"
RETIRED_CONTENT_ACCRUAL_REASON = "reputation_delta_requires_dispute_resolve_parent"


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
    """Return the legacy maturity parameter for state compatibility only."""

    params = _params(state)
    raw = params.get("content_reputation_maturity_blocks")
    if raw is None:
        raw = _as_dict(params.get("reputation")).get("content_maturity_blocks")
    return max(1, _as_int(raw, DEFAULT_CONTENT_REPUTATION_MATURITY_BLOCKS))


def post_reputation_delta_milli(state: Json) -> int:
    """Return the legacy post delta parameter for state compatibility only."""

    params = _params(state)
    raw = params.get("post_reputation_delta_milli")
    if raw is None:
        raw = _as_dict(params.get("reputation")).get("post_delta_milli")
    return max(0, _as_int(raw, DEFAULT_POST_REPUTATION_DELTA_MILLI))


def media_reputation_delta_milli(state: Json) -> int:
    """Return the legacy media delta parameter for state compatibility only."""

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
    """Construct deterministic retired metadata instead of actionable work.

    The historical field shape is retained so state consumers do not need an
    unrelated migration merely to remove an invalid issuance path.
    """

    return {
        "kind": str(kind),
        "source_id": str(source_id),
        "account_id": str(account_id),
        "created_height": int(created_height),
        "matures_at_height": int(created_height) + int(maturity_blocks),
        "delta_milli": int(delta_milli),
        "status": RETIRED_CONTENT_ACCRUAL_STATUS,
        "retired_reason": RETIRED_CONTENT_ACCRUAL_REASON,
    }


def _retire_pending_record(rec: Json) -> bool:
    accrual = _as_dict(rec.get("reputation_accrual"))
    if not accrual:
        return False
    if _as_str(accrual.get("status")).strip().lower() != "pending":
        return False

    accrual["status"] = RETIRED_CONTENT_ACCRUAL_STATUS
    accrual["retired_reason"] = RETIRED_CONTENT_ACCRUAL_REASON
    rec["reputation_accrual"] = accrual
    return True


def schedule_reputation_accrual_system_txs(state: Json, *, next_height: int) -> int:
    """Retire legacy pending content accruals without emitting SYSTEM txs.

    ``next_height`` remains part of the scheduler signature because the
    canonical scheduler pipeline invokes all schedulers uniformly. It is not
    used to create reputation work: content age alone is not valid provenance
    for ``REPUTATION_DELTA_APPLY``.
    """

    del next_height

    content = _as_dict(state.get("content"))
    if not content:
        return 0

    for lane_name in ("posts", "media"):
        lane = content.get(lane_name)
        if not isinstance(lane, dict):
            continue
        for _source_id, rec_any in sorted(lane.items()):
            rec = _as_dict(rec_any)
            _retire_pending_record(rec)

    return 0


__all__ = [
    "DEFAULT_CONTENT_REPUTATION_MATURITY_BLOCKS",
    "DEFAULT_MEDIA_REPUTATION_DELTA_MILLI",
    "DEFAULT_POST_REPUTATION_DELTA_MILLI",
    "RETIRED_CONTENT_ACCRUAL_REASON",
    "RETIRED_CONTENT_ACCRUAL_STATUS",
    "content_reputation_maturity_blocks",
    "media_reputation_delta_milli",
    "pending_content_accrual",
    "post_reputation_delta_milli",
    "schedule_reputation_accrual_system_txs",
]
