from __future__ import annotations

"""Content contribution reputation metadata.

Reputation is responsibility history, not a prerequisite for becoming human.

The historical maturity scheduler in this module used to emit
``REPUTATION_DELTA_APPLY`` directly for mature posts/media. That path is now
intentionally retired: the transaction canon binds ``REPUTATION_DELTA_APPLY``
to its declared causal reputation/dispute lineage, so content maturity alone
must not manufacture a canonical reputation delta.

The metadata helpers remain because content records still carry deterministic
maturity information that can be consumed by a future canon-declared mechanism
without silently reactivating the retired SYSTEM issuance path.
"""

from typing import Any

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
    """Return deterministic legacy contribution metadata without granting reputation."""

    return {
        "kind": str(kind),
        "source_id": str(source_id),
        "account_id": str(account_id),
        "created_height": int(created_height),
        "matures_at_height": int(created_height) + int(maturity_blocks),
        "delta_milli": int(delta_milli),
        "status": "pending",
    }


def schedule_reputation_accrual_system_txs(state: Json, *, next_height: int) -> int:
    """Do not emit maturity-only reputation transactions.

    This function deliberately remains in the scheduler interface so leader and
    replay pipelines keep the same deterministic call graph. It is a no-op until
    a future transaction-canon revision declares an explicit causal mechanism for
    content-contribution reputation. In particular, this function must not emit
    ``REPUTATION_DELTA_APPLY`` merely because a post or media record matured.
    """

    _ = state
    _ = int(next_height)
    return 0


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
