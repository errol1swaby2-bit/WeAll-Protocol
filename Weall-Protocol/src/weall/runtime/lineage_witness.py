"""Pure causal-lineage witness model for canonical parent relationships.

This module intentionally has no runtime integration.  It defines the data
contract, canonicalization, commitments, and fail-closed validation needed
before parent-lineage enforcement is wired into queue, block, or replay paths.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from weall.runtime.commitments import canonical_json_sha256
from weall.runtime.json_tools import canonical_json_str

Json = dict[str, Any]

LINEAGE_WITNESS_VERSION = 1
_TX_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_TX_ID_RE = re.compile(r"^tx:[0-9a-f]{64}$")
_SHA256_COMMITMENT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LineageWitnessKind(StrEnum):
    SINGLE_TX = "SINGLE_TX"
    TX_SET = "TX_SET"
    CERTIFICATE = "CERTIFICATE"
    SCOPED_STATE = "SCOPED_STATE"


class LineageWitnessError(ValueError):
    """Raised when a lineage witness cannot be canonicalized safely."""


@dataclass(frozen=True, slots=True)
class LineageWitness:
    version: int
    kind: LineageWitnessKind
    parent_tx_type: str
    scope: str = ""
    parent_tx_id: str = ""
    parent_tx_ids: tuple[str, ...] = ()
    same_block_position: int | None = None
    set_commitment: str = ""
    policy_id: str = ""
    required_count: int | None = None
    certificate_type: str = ""
    certificate_commitment: str = ""
    subject_id: str = ""
    created_height: int | None = None
    updated_height: int | None = None
    source: LineageWitness | None = None

    def to_json(self) -> Json:
        base: Json = {
            "version": self.version,
            "kind": self.kind.value,
            "parent_tx_type": self.parent_tx_type,
        }
        if self.kind is LineageWitnessKind.SINGLE_TX:
            base["parent_tx_id"] = self.parent_tx_id
            if self.scope:
                base["scope"] = self.scope
            if self.same_block_position is not None:
                base["same_block_position"] = self.same_block_position
            return base
        if self.kind is LineageWitnessKind.TX_SET:
            base.update(
                {
                    "parent_tx_ids": list(self.parent_tx_ids),
                    "set_commitment": self.set_commitment,
                    "scope": self.scope,
                    "policy_id": self.policy_id,
                }
            )
            if self.required_count is not None:
                base["required_count"] = self.required_count
            return base
        if self.kind is LineageWitnessKind.CERTIFICATE:
            base.update(
                {
                    "certificate_type": self.certificate_type,
                    "certificate_commitment": self.certificate_commitment,
                    "subject_id": self.subject_id,
                    "policy_id": self.policy_id,
                }
            )
            if self.scope:
                base["scope"] = self.scope
            return base
        if self.kind is LineageWitnessKind.SCOPED_STATE:
            if self.source is None:
                raise LineageWitnessError("scoped_state_source_missing")
            if self.created_height is None or self.updated_height is None:
                raise LineageWitnessError("scoped_state_height_missing")
            base.update(
                {
                    "scope": self.scope,
                    "created_height": self.created_height,
                    "updated_height": self.updated_height,
                    "source": self.source.to_json(),
                }
            )
            return base
        raise LineageWitnessError("unsupported_lineage_witness_kind")


@dataclass(frozen=True, slots=True)
class LineageWitnessValidation:
    ok: bool
    reason: str
    witness: LineageWitness | None = None
    commitment: str = ""


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise LineageWitnessError(f"{field}_must_be_string")
    out = value.strip()
    if not out:
        raise LineageWitnessError(f"{field}_required")
    return out


def _optional_str(value: Any, field: str) -> str:
    if value is None or value == "":
        return ""
    return _require_str(value, field)


def _require_nonnegative_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LineageWitnessError(f"{field}_must_be_integer")
    if value < 0:
        raise LineageWitnessError(f"{field}_must_be_nonnegative")
    return value


def _optional_nonnegative_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _require_nonnegative_int(value, field)


def _normalize_parent_tx_type(value: Any) -> str:
    out = _require_str(value, "parent_tx_type").upper()
    if not _TX_TYPE_RE.fullmatch(out):
        raise LineageWitnessError("parent_tx_type_invalid")
    return out


def _normalize_tx_id(value: Any, field: str = "parent_tx_id") -> str:
    out = _require_str(value, field)
    if not _TX_ID_RE.fullmatch(out):
        raise LineageWitnessError(f"{field}_not_canonical_tx_id")
    return out


def _normalize_sha256_commitment(value: Any, field: str) -> str:
    out = _require_str(value, field)
    if not _SHA256_COMMITMENT_RE.fullmatch(out):
        raise LineageWitnessError(f"{field}_not_sha256_commitment")
    return out


def _normalize_kind(value: Any) -> LineageWitnessKind:
    raw = _require_str(value, "kind").upper()
    try:
        return LineageWitnessKind(raw)
    except ValueError as exc:
        raise LineageWitnessError("unsupported_lineage_witness_kind") from exc


def _normalize_tx_ids(values: Any) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise LineageWitnessError("parent_tx_ids_must_be_sequence")
    normalized = tuple(_normalize_tx_id(value, "parent_tx_ids_item") for value in values)
    if not normalized:
        raise LineageWitnessError("parent_tx_ids_required")
    if len(set(normalized)) != len(normalized):
        raise LineageWitnessError("parent_tx_ids_duplicate")
    return tuple(sorted(normalized))


def _reject_unknown_keys(value: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise LineageWitnessError("unknown_fields:" + ",".join(unknown))


def lineage_tx_set_commitment(
    *,
    parent_tx_type: str,
    parent_tx_ids: Sequence[str],
    scope: str,
    policy_id: str,
) -> str:
    normalized_parent = _normalize_parent_tx_type(parent_tx_type)
    normalized_ids = _normalize_tx_ids(parent_tx_ids)
    normalized_scope = _require_str(scope, "scope")
    normalized_policy = _require_str(policy_id, "policy_id")
    payload = {
        "t": "WEALL_LINEAGE_TX_SET_V1",
        "parent_tx_type": normalized_parent,
        "parent_tx_ids": list(normalized_ids),
        "scope": normalized_scope,
        "policy_id": normalized_policy,
    }
    return "sha256:" + canonical_json_sha256(payload)


def lineage_certificate_commitment(certificate: Mapping[str, Any]) -> str:
    return "sha256:" + canonical_json_sha256(
        {"t": "WEALL_LINEAGE_CERTIFICATE_V1", "certificate": dict(certificate)}
    )


def make_single_tx_witness(
    *,
    parent_tx_type: str,
    parent_tx_id: str,
    scope: str = "",
    same_block_position: int | None = None,
) -> LineageWitness:
    return LineageWitness(
        version=LINEAGE_WITNESS_VERSION,
        kind=LineageWitnessKind.SINGLE_TX,
        parent_tx_type=_normalize_parent_tx_type(parent_tx_type),
        parent_tx_id=_normalize_tx_id(parent_tx_id),
        scope=_optional_str(scope, "scope"),
        same_block_position=_optional_nonnegative_int(same_block_position, "same_block_position"),
    )


def make_tx_set_witness(
    *,
    parent_tx_type: str,
    parent_tx_ids: Sequence[str],
    scope: str,
    policy_id: str,
    required_count: int | None = None,
) -> LineageWitness:
    normalized_parent = _normalize_parent_tx_type(parent_tx_type)
    normalized_ids = _normalize_tx_ids(parent_tx_ids)
    normalized_scope = _require_str(scope, "scope")
    normalized_policy = _require_str(policy_id, "policy_id")
    normalized_required = _optional_nonnegative_int(required_count, "required_count")
    if normalized_required == 0:
        raise LineageWitnessError("required_count_must_be_positive")
    if normalized_required is not None and normalized_required > len(normalized_ids):
        raise LineageWitnessError("required_count_exceeds_parent_tx_ids")
    return LineageWitness(
        version=LINEAGE_WITNESS_VERSION,
        kind=LineageWitnessKind.TX_SET,
        parent_tx_type=normalized_parent,
        parent_tx_ids=normalized_ids,
        scope=normalized_scope,
        policy_id=normalized_policy,
        required_count=normalized_required,
        set_commitment=lineage_tx_set_commitment(
            parent_tx_type=normalized_parent,
            parent_tx_ids=normalized_ids,
            scope=normalized_scope,
            policy_id=normalized_policy,
        ),
    )


def make_certificate_witness(
    *,
    parent_tx_type: str,
    certificate_type: str,
    certificate_commitment: str,
    subject_id: str,
    policy_id: str,
    scope: str = "",
) -> LineageWitness:
    return LineageWitness(
        version=LINEAGE_WITNESS_VERSION,
        kind=LineageWitnessKind.CERTIFICATE,
        parent_tx_type=_normalize_parent_tx_type(parent_tx_type),
        certificate_type=_require_str(certificate_type, "certificate_type"),
        certificate_commitment=_normalize_sha256_commitment(
            certificate_commitment, "certificate_commitment"
        ),
        subject_id=_require_str(subject_id, "subject_id"),
        policy_id=_require_str(policy_id, "policy_id"),
        scope=_optional_str(scope, "scope"),
    )


def make_scoped_state_witness(
    *,
    parent_tx_type: str,
    scope: str,
    created_height: int,
    updated_height: int,
    source: LineageWitness,
) -> LineageWitness:
    normalized_parent = _normalize_parent_tx_type(parent_tx_type)
    normalized_scope = _require_str(scope, "scope")
    created = _require_nonnegative_int(created_height, "created_height")
    updated = _require_nonnegative_int(updated_height, "updated_height")
    if updated < created:
        raise LineageWitnessError("updated_height_before_created_height")
    if not isinstance(source, LineageWitness):
        raise LineageWitnessError("scoped_state_source_must_be_witness")
    if source.kind is LineageWitnessKind.SCOPED_STATE:
        raise LineageWitnessError("nested_scoped_state_not_allowed")
    if source.parent_tx_type != normalized_parent:
        raise LineageWitnessError("scoped_state_source_parent_tx_type_mismatch")
    return LineageWitness(
        version=LINEAGE_WITNESS_VERSION,
        kind=LineageWitnessKind.SCOPED_STATE,
        parent_tx_type=normalized_parent,
        scope=normalized_scope,
        created_height=created,
        updated_height=updated,
        source=source,
    )


def canonicalize_lineage_witness(value: Mapping[str, Any] | LineageWitness) -> Json:
    if isinstance(value, LineageWitness):
        return canonicalize_lineage_witness(value.to_json())
    if not isinstance(value, Mapping):
        raise LineageWitnessError("lineage_witness_must_be_mapping")

    version = value.get("version", LINEAGE_WITNESS_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        raise LineageWitnessError("version_must_be_integer")
    if version != LINEAGE_WITNESS_VERSION:
        raise LineageWitnessError("unsupported_lineage_witness_version")

    kind = _normalize_kind(value.get("kind"))
    parent_tx_type = _normalize_parent_tx_type(value.get("parent_tx_type"))

    common = {"version", "kind", "parent_tx_type"}
    if kind is LineageWitnessKind.SINGLE_TX:
        _reject_unknown_keys(
            value,
            common | {"parent_tx_id", "scope", "same_block_position"},
        )
        witness = make_single_tx_witness(
            parent_tx_type=parent_tx_type,
            parent_tx_id=value.get("parent_tx_id"),
            scope=value.get("scope", ""),
            same_block_position=value.get("same_block_position"),
        )
        return witness.to_json()

    if kind is LineageWitnessKind.TX_SET:
        _reject_unknown_keys(
            value,
            common
            | {
                "parent_tx_ids",
                "set_commitment",
                "scope",
                "policy_id",
                "required_count",
            },
        )
        witness = make_tx_set_witness(
            parent_tx_type=parent_tx_type,
            parent_tx_ids=value.get("parent_tx_ids"),
            scope=value.get("scope"),
            policy_id=value.get("policy_id"),
            required_count=value.get("required_count"),
        )
        provided = value.get("set_commitment", witness.set_commitment)
        provided_commitment = _normalize_sha256_commitment(provided, "set_commitment")
        if provided_commitment != witness.set_commitment:
            raise LineageWitnessError("set_commitment_mismatch")
        return witness.to_json()

    if kind is LineageWitnessKind.CERTIFICATE:
        _reject_unknown_keys(
            value,
            common
            | {
                "certificate_type",
                "certificate_commitment",
                "subject_id",
                "policy_id",
                "scope",
            },
        )
        return make_certificate_witness(
            parent_tx_type=parent_tx_type,
            certificate_type=value.get("certificate_type"),
            certificate_commitment=value.get("certificate_commitment"),
            subject_id=value.get("subject_id"),
            policy_id=value.get("policy_id"),
            scope=value.get("scope", ""),
        ).to_json()

    if kind is LineageWitnessKind.SCOPED_STATE:
        _reject_unknown_keys(
            value,
            common | {"scope", "created_height", "updated_height", "source"},
        )
        source_raw = value.get("source")
        if not isinstance(source_raw, Mapping):
            raise LineageWitnessError("scoped_state_source_must_be_mapping")
        source_json = canonicalize_lineage_witness(source_raw)
        source = lineage_witness_from_json(source_json)
        return make_scoped_state_witness(
            parent_tx_type=parent_tx_type,
            scope=value.get("scope"),
            created_height=value.get("created_height"),
            updated_height=value.get("updated_height"),
            source=source,
        ).to_json()

    raise LineageWitnessError("unsupported_lineage_witness_kind")


def lineage_witness_from_json(value: Mapping[str, Any]) -> LineageWitness:
    canonical = canonicalize_lineage_witness(value)
    kind = LineageWitnessKind(canonical["kind"])
    if kind is LineageWitnessKind.SINGLE_TX:
        return make_single_tx_witness(
            parent_tx_type=canonical["parent_tx_type"],
            parent_tx_id=canonical["parent_tx_id"],
            scope=canonical.get("scope", ""),
            same_block_position=canonical.get("same_block_position"),
        )
    if kind is LineageWitnessKind.TX_SET:
        return make_tx_set_witness(
            parent_tx_type=canonical["parent_tx_type"],
            parent_tx_ids=canonical["parent_tx_ids"],
            scope=canonical["scope"],
            policy_id=canonical["policy_id"],
            required_count=canonical.get("required_count"),
        )
    if kind is LineageWitnessKind.CERTIFICATE:
        return make_certificate_witness(
            parent_tx_type=canonical["parent_tx_type"],
            certificate_type=canonical["certificate_type"],
            certificate_commitment=canonical["certificate_commitment"],
            subject_id=canonical["subject_id"],
            policy_id=canonical["policy_id"],
            scope=canonical.get("scope", ""),
        )
    source = lineage_witness_from_json(canonical["source"])
    return make_scoped_state_witness(
        parent_tx_type=canonical["parent_tx_type"],
        scope=canonical["scope"],
        created_height=canonical["created_height"],
        updated_height=canonical["updated_height"],
        source=source,
    )


def lineage_witness_commitment(value: Mapping[str, Any] | LineageWitness) -> str:
    canonical = canonicalize_lineage_witness(value)
    return "sha256:" + canonical_json_sha256(
        {"t": "WEALL_LINEAGE_WITNESS_V1", "witness": canonical}
    )


def validate_lineage_witness(
    value: Mapping[str, Any] | LineageWitness,
    *,
    expected_parent_tx_type: str | None = None,
    require_canonical: bool = True,
) -> LineageWitnessValidation:
    try:
        canonical = canonicalize_lineage_witness(value)
        witness = lineage_witness_from_json(canonical)
        if expected_parent_tx_type is not None:
            expected = _normalize_parent_tx_type(expected_parent_tx_type)
            if witness.parent_tx_type != expected:
                return LineageWitnessValidation(False, "parent_tx_type_mismatch")
        if require_canonical and isinstance(value, Mapping):
            raw = canonical_json_str(dict(value))
            normalized = canonical_json_str(canonical)
            if raw != normalized:
                return LineageWitnessValidation(False, "noncanonical_lineage_witness")
        return LineageWitnessValidation(
            True,
            "",
            witness=witness,
            commitment=lineage_witness_commitment(witness),
        )
    except (TypeError, ValueError) as exc:
        return LineageWitnessValidation(False, str(exc))


__all__ = [
    "LINEAGE_WITNESS_VERSION",
    "LineageWitness",
    "LineageWitnessError",
    "LineageWitnessKind",
    "LineageWitnessValidation",
    "canonicalize_lineage_witness",
    "lineage_certificate_commitment",
    "lineage_tx_set_commitment",
    "lineage_witness_commitment",
    "lineage_witness_from_json",
    "make_certificate_witness",
    "make_scoped_state_witness",
    "make_single_tx_witness",
    "make_tx_set_witness",
    "validate_lineage_witness",
]
