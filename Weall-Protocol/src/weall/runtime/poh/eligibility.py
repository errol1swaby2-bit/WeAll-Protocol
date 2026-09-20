from __future__ import annotations

"""Canon-backed PoH minimum-tier eligibility adapter.

Production transaction admission is authoritative and evaluates the
``subject_gate`` in ``generated/tx_index.json``. This module deliberately does
not maintain a second transaction-name policy table.

Context-specific apply rules may be stricter than this canonical minimum. For
example ``CONTENT_COMMENT_CREATE`` is Tier0+ because the public lobby is Tier0,
while non-lobby comments are additionally constrained by the content applier.
"""

from collections.abc import Mapping
from functools import lru_cache
from types import MappingProxyType
from typing import Any

from weall.runtime.errors import ApplyError
from weall.runtime.poh.state import effective_poh_tier
from weall.tx.canon import TxIndex, default_tx_canon_paths

Json = dict[str, Any]
UNKNOWN_ACTION_REQUIRED_POH_TIER = 99


def normalize_action_name(action_name: str) -> str:
    return str(action_name or "").strip().upper()


def is_removed_legacy_poh_tier_action(action_name: str) -> bool:
    name = normalize_action_name(action_name)
    return ("TIER" + "3") in name or name.startswith("POH_" + "TIER" + "3" + "_")


def _tier_from_subject_gate(gate: str) -> int | None:
    value = str(gate or "").strip()
    if not (value.startswith("Tier") and value.endswith("+")):
        return None
    raw = value[4:-1]
    return int(raw) if raw in {"0", "1", "2"} else None


@lru_cache(maxsize=1)
def _canonical_tx_index() -> TxIndex:
    return TxIndex.load_from_file(default_tx_canon_paths().out_path)


def _build_canonical_tier_map() -> dict[str, int]:
    out: dict[str, int] = {}
    for name, spec in _canonical_tx_index().by_name.items():
        tier = _tier_from_subject_gate(str(spec.get("subject_gate") or ""))
        if tier is not None:
            out[str(name).upper()] = tier
    return dict(sorted(out.items()))


ACTION_REQUIRED_POH_TIER: Mapping[str, int] = MappingProxyType(_build_canonical_tier_map())


def get_required_poh_tier(action_name: str) -> int:
    if is_removed_legacy_poh_tier_action(action_name):
        return UNKNOWN_ACTION_REQUIRED_POH_TIER
    return int(
        ACTION_REQUIRED_POH_TIER.get(
            normalize_action_name(action_name), UNKNOWN_ACTION_REQUIRED_POH_TIER
        )
    )


def can_account_perform_action(state: Json, account_id: str, action_name: str) -> bool:
    required = get_required_poh_tier(action_name)
    if required == UNKNOWN_ACTION_REQUIRED_POH_TIER:
        return False
    return effective_poh_tier(state, account_id) >= required


def require_poh_tier(state: Json, account_id: str, action_name: str) -> None:
    if is_removed_legacy_poh_tier_action(action_name):
        raise ApplyError(
            "forbidden",
            "removed_legacy_poh_tier_action",
            {
                "account_id": str(account_id or "").strip(),
                "tx_type": normalize_action_name(action_name),
                "max_tier": 2,
            },
        )
    name = normalize_action_name(action_name)
    required = get_required_poh_tier(name)
    if required == UNKNOWN_ACTION_REQUIRED_POH_TIER:
        raise ApplyError(
            "forbidden",
            "unknown_poh_eligibility_action",
            {"account_id": str(account_id or "").strip(), "tx_type": name, "max_tier": 2},
        )
    actual = effective_poh_tier(state, account_id)
    if actual < required:
        raise ApplyError(
            "forbidden",
            "poh_tier_required",
            {
                "account_id": str(account_id or "").strip(),
                "tx_type": name,
                "required_tier": required,
                "actual_tier": actual,
            },
        )
