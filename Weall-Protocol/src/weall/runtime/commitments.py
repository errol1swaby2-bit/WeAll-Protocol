from __future__ import annotations

"""Canonical deterministic commitment primitives shared across runtime domains."""

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from weall.runtime.json_tools import canonical_json_str


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_str(value).encode("utf-8")).hexdigest()


def canonical_json_sha256_ascii(value: Any) -> str:
    """Hash the historic ensure_ascii=True canonical JSON encoding."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_validator_ids(validators: Iterable[str]) -> list[str]:
    normalized: set[str] = set()
    for value in validators:
        if not isinstance(value, (str, int, float)):
            continue
        item = str(value).strip()
        if item:
            normalized.add(item)
    return sorted(normalized)




def first_validator_member_key_authority_issue(
    state: Mapping[str, Any],
    members: Iterable[str],
    *,
    normalize_pubkey: Callable[[Any], str],
) -> tuple[str, str] | None:
    """Inspect both canonical key registries without changing ledger state.

    Callers retain their own activation/recovery gate and historic error
    contracts. The supplied key normalizer preserves each boundary's existing
    treatment of malformed legacy pubkeys; successful, valid key matches use
    one common predicate regardless of which boundary checks them.
    """
    validators_root = state.get("validators")
    lifecycle_registry = (
        validators_root.get("registry") if isinstance(validators_root, dict) else None
    )
    lifecycle_registry = lifecycle_registry if isinstance(lifecycle_registry, dict) else {}
    consensus = state.get("consensus")
    validators = consensus.get("validators") if isinstance(consensus, dict) else None
    consensus_registry = validators.get("registry") if isinstance(validators, dict) else None
    consensus_registry = consensus_registry if isinstance(consensus_registry, dict) else {}

    for account in members:
        lifecycle_rec = lifecycle_registry.get(account)
        if not isinstance(lifecycle_rec, dict):
            return "member_not_registered", account
        canonical_pubkey = normalize_pubkey(lifecycle_rec.get("pubkey") or "")
        if not canonical_pubkey:
            return "missing_canonical_pubkey", account
        consensus_rec = consensus_registry.get(account)
        consensus_pubkey = (
            normalize_pubkey(consensus_rec.get("pubkey") or "")
            if isinstance(consensus_rec, dict)
            else ""
        )
        if not consensus_pubkey:
            return "missing_consensus_pubkey", account
        if consensus_pubkey != canonical_pubkey:
            return "pubkey_mismatch", account
    return None


def consensus_active_validator_ids(state: Mapping[str, Any]) -> list[str] | None:
    """Return materialized consensus membership, or ``None`` for legacy fallback.

    ``None`` means the canonical ``active_set`` field has not been declared yet,
    so callers may consult a documented legacy authority source. Once that field
    is declared it is authoritative. A malformed declared value therefore fails
    closed as an empty set instead of reactivating legacy validator membership.
    """

    consensus = state.get("consensus") if isinstance(state, Mapping) else None
    if not isinstance(consensus, Mapping):
        return None
    if "validator_set" not in consensus:
        return None
    validator_set = consensus.get("validator_set")
    if not isinstance(validator_set, Mapping):
        return []
    if "active_set" not in validator_set:
        return None
    active_set = validator_set.get("active_set")
    if not isinstance(active_set, list):
        return []
    return normalize_validator_ids(active_set)


def consensus_validator_generation(state: Mapping[str, Any]) -> int | None:
    """Return the declared validator-set generation, or ``None`` if legacy.

    A present-but-malformed generation is authority corruption, not absence. It
    therefore resolves to generation zero so callers fail closed instead of
    substituting the unrelated protocol epoch clock. Explicit generation zero is
    also authoritative and is preserved for pre-activation/genesis state.
    """

    consensus = state.get("consensus") if isinstance(state, Mapping) else None
    if not isinstance(consensus, Mapping):
        return None
    if "validator_set" not in consensus:
        return None
    validator_set = consensus.get("validator_set")
    if not isinstance(validator_set, Mapping):
        return 0
    if "epoch" not in validator_set:
        return None
    raw = validator_set.get("epoch")
    if isinstance(raw, bool):
        return 0
    try:
        generation = int(raw)
    except (TypeError, ValueError, OverflowError):
        return 0
    return generation if generation >= 0 else 0


def value_sha256(value: Any) -> str:
    """Preserve the protocol's historic raw-string / canonical-object hash rule."""
    if isinstance(value, str):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
    return canonical_json_sha256(value)


def validator_set_hash(validators: Iterable[str]) -> str:
    return canonical_json_sha256(normalize_validator_ids(validators))


def receipts_root(receipts: Sequence[Mapping[str, Any]]) -> str:
    return canonical_json_sha256([dict(item) for item in receipts])
