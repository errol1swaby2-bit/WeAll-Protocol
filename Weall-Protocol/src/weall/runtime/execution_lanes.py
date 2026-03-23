from __future__ import annotations

from dataclasses import dataclass
from typing import Any

Json = dict[str, Any]

LANE_SERIAL = "SERIAL"
LANE_PARALLEL_IDENTITY = "PARALLEL_IDENTITY"
LANE_PARALLEL_SOCIAL = "PARALLEL_SOCIAL"
LANE_PARALLEL_CONTENT = "PARALLEL_CONTENT"
LANE_PARALLEL_ECONOMY = "PARALLEL_ECONOMY"

ALL_LANES: tuple[str, ...] = (
    LANE_SERIAL,
    LANE_PARALLEL_IDENTITY,
    LANE_PARALLEL_SOCIAL,
    LANE_PARALLEL_CONTENT,
    LANE_PARALLEL_ECONOMY,
)


@dataclass(frozen=True, slots=True)
class LaneRule:
    lane_id: str
    allowed_tx_prefixes: tuple[str, ...]
    allowed_state_prefixes: tuple[str, ...]
    helper_allowed: bool
    fallback_to_serial_on_ambiguity: bool = True

    def allows_tx_type(self, tx_type: str) -> bool:
        tx_type2 = str(tx_type or "").strip().upper()
        if not tx_type2:
            return False
        return any(tx_type2.startswith(prefix) for prefix in self.allowed_tx_prefixes)

    def allows_namespace_prefix(self, key_prefix: str) -> bool:
        key_prefix2 = str(key_prefix or "").strip().lower()
        if not key_prefix2:
            return False
        return any(
            key_prefix2 == prefix or key_prefix2.startswith(prefix)
            for prefix in self.allowed_state_prefixes
        )


LANE_RULES: dict[str, LaneRule] = {
    LANE_SERIAL: LaneRule(
        lane_id=LANE_SERIAL,
        allowed_tx_prefixes=(),
        allowed_state_prefixes=(),
        helper_allowed=False,
        fallback_to_serial_on_ambiguity=True,
    ),
    LANE_PARALLEL_IDENTITY: LaneRule(
        lane_id=LANE_PARALLEL_IDENTITY,
        allowed_tx_prefixes=("IDENTITY_", "POH_"),
        allowed_state_prefixes=("identity:", "poh:"),
        helper_allowed=True,
    ),
    LANE_PARALLEL_SOCIAL: LaneRule(
        lane_id=LANE_PARALLEL_SOCIAL,
        allowed_tx_prefixes=("SOCIAL_", "REPUTATION_", "NOTIFICATION_", "MESSAGING_"),
        allowed_state_prefixes=("social:", "reputation:", "notifications:", "messaging:"),
        helper_allowed=True,
    ),
    LANE_PARALLEL_CONTENT: LaneRule(
        lane_id=LANE_PARALLEL_CONTENT,
        allowed_tx_prefixes=("CONTENT_", "STORAGE_", "INDEXING_"),
        allowed_state_prefixes=("content:", "storage:", "indexing:"),
        helper_allowed=True,
    ),
    LANE_PARALLEL_ECONOMY: LaneRule(
        lane_id=LANE_PARALLEL_ECONOMY,
        allowed_tx_prefixes=("ECONOMICS_", "TREASURY_", "REWARDS_"),
        allowed_state_prefixes=("economy:", "treasury:", "rewards:"),
        helper_allowed=True,
    ),
}


def get_lane_rule(lane_id: str) -> LaneRule:
    lane_id2 = str(lane_id or "").strip().upper()
    return LANE_RULES.get(lane_id2, LANE_RULES[LANE_SERIAL])


AUTHORITY_HEAVY_TX_PREFIXES: tuple[str, ...] = (
    "GOV_",
    "ROLE_",
    "ROLES_",
    "VALIDATOR_",
    "CONSENSUS_",
    "DISPUTE_",
    "GROUP_",
    "CASE_",
    "MODERATION_",
    "NETWORK_",
    "SYSTEM_",
)


SERIAL_NAMESPACE_PREFIXES: tuple[str, ...] = (
    "gov:",
    "governance:",
    "roles:",
    "validators:",
    "validator_set:",
    "consensus:",
    "dispute:",
    "groups:",
    "cases:",
    "moderation:",
    "network:",
    "system:",
)


AMBIGUOUS_SCOPE_SENTINELS: frozenset[str] = frozenset(
    {
        "*",
        "any",
        "unknown",
        "dynamic",
        "cross_domain",
        "cross-domain",
        "cross_lane",
        "cross-lane",
        "global",
    }
)


INFERRED_NAMESPACE_BY_TX_PREFIX: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ACCOUNT_", ("identity:",)),
    ("IDENTITY_", ("identity:",)),
    ("POH_", ("poh:",)),
    ("SOCIAL_", ("social:",)),
    ("REPUTATION_", ("reputation:",)),
    ("NOTIFICATION_", ("notifications:",)),
    ("MESSAGING_", ("messaging:",)),
    ("CONTENT_", ("content:",)),
    ("STORAGE_", ("storage:",)),
    ("INDEXING_", ("indexing:",)),
    ("TREASURY_", ("treasury:",)),
    ("ECONOMICS_", ("economy:",)),
    ("REWARDS_", ("rewards:",)),
)


def _infer_scope_prefixes_from_tx_type(tx: Json) -> tuple[str, ...]:
    tx_type = tx_type_of(tx)
    if not tx_type:
        return ()
    matches: list[tuple[str, ...]] = []
    for prefix, namespaces in INFERRED_NAMESPACE_BY_TX_PREFIX:
        if tx_type.startswith(prefix):
            matches.append(namespaces)
    if len(matches) != 1:
        return ()
    inferred = sorted({str(item).strip().lower() for item in matches[0] if str(item).strip()})
    return tuple(inferred)


def canonical_scope_prefixes(tx: Json) -> tuple[str, ...]:
    raw = tx.get("state_prefixes")
    if not isinstance(raw, list):
        raw = tx.get("touched_prefixes")
    if not isinstance(raw, list):
        raw = []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        s = str(item or "").strip().lower()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    if not out:
        out.extend(list(_infer_scope_prefixes_from_tx_type(tx)))
    out.sort()
    return tuple(out)


def tx_type_of(tx: Json) -> str:
    return str(tx.get("tx_type") or tx.get("type") or "").strip().upper()


def is_scope_ambiguous(tx: Json) -> bool:
    scope = canonical_scope_prefixes(tx)
    if not scope:
        return True
    for prefix in scope:
        if prefix in AMBIGUOUS_SCOPE_SENTINELS:
            return True
        if not prefix.endswith(":") and ":" not in prefix:
            return True
    return False


def requires_serial_due_to_authority(tx: Json) -> bool:
    tx_type = tx_type_of(tx)
    if any(tx_type.startswith(prefix) for prefix in AUTHORITY_HEAVY_TX_PREFIXES):
        return True
    scope = canonical_scope_prefixes(tx)
    return any(
        any(prefix == banned or prefix.startswith(banned) for banned in SERIAL_NAMESPACE_PREFIXES)
        for prefix in scope
    )
