from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .errors import ContractError
from .util import canonical_json_sha256


class EvidenceKind(str, Enum):
    DIRECT_TRANSACTION = "direct_transaction"
    INLINE_SYSTEM_TRANSITION = "inline_system_transition"
    ACCEPTANCE_EMBEDDED_ATTENDANCE = "acceptance_embedded_attendance"


TERMINAL_STATUSES = frozenset({"confirmed", "committed", "finalized"})


def _required_text(raw: Mapping[str, Any], field: str, index: int) -> str:
    value = str(raw.get(field) or "").strip()
    if not value:
        raise ContractError(f"action[{index}].{field}_missing")
    return value


def _required_int(raw: Mapping[str, Any], field: str, index: int) -> int:
    value = raw.get(field)
    if isinstance(value, bool):
        raise ContractError(f"action[{index}].{field}_invalid")
    try:
        resolved = int(value)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"action[{index}].{field}_invalid") from exc
    return resolved


@dataclass(frozen=True)
class DirectTransactionAction:
    index: int
    label: str
    role: str
    account: str
    tx_type: str
    tx_id: str
    subject_id: str
    status: str
    evidence_kind: EvidenceKind = EvidenceKind.DIRECT_TRANSACTION

    @property
    def status_query_tx_id(self) -> str:
        return self.tx_id


@dataclass(frozen=True)
class EmbeddedAttendanceAction:
    index: int
    label: str
    role: str
    account: str
    tx_type: str
    tx_id: str
    subject_id: str
    status: str
    evidence_kind: EvidenceKind = EvidenceKind.ACCEPTANCE_EMBEDDED_ATTENDANCE

    @property
    def status_query_tx_id(self) -> str:
        return self.tx_id


@dataclass(frozen=True)
class InlineSystemTransitionAction:
    index: int
    label: str
    role: str
    account: str
    tx_type: str
    tx_id: str
    subject_id: str
    status: str
    trigger_tx_id: str
    trigger_included_height: int
    state_height: int
    evidence_kind: EvidenceKind = EvidenceKind.INLINE_SYSTEM_TRANSITION

    @property
    def status_query_tx_id(self) -> str:
        return self.trigger_tx_id


EvidenceAction = (
    DirectTransactionAction
    | EmbeddedAttendanceAction
    | InlineSystemTransitionAction
)


@dataclass(frozen=True)
class Transcript:
    schema_version: int
    implementation_freeze_commit: str
    chain_id: str
    actions: tuple[EvidenceAction, ...]
    negative_attempts: tuple[Mapping[str, Any], ...]
    source_sha256: str

    @property
    def fingerprint(self) -> str:
        return canonical_json_sha256(
            {
                "schema_version": self.schema_version,
                "implementation_freeze_commit": self.implementation_freeze_commit,
                "chain_id": self.chain_id,
                "actions": [
                    {
                        "index": action.index,
                        "evidence_kind": action.evidence_kind.value,
                        "label": action.label,
                        "role": action.role,
                        "account": action.account,
                        "tx_type": action.tx_type,
                        "tx_id": action.tx_id,
                        "subject_id": action.subject_id,
                        "status": action.status,
                        "status_query_tx_id": action.status_query_tx_id,
                        **(
                            {
                                "trigger_included_height": action.trigger_included_height,
                                "state_height": action.state_height,
                            }
                            if isinstance(action, InlineSystemTransitionAction)
                            else {}
                        ),
                    }
                    for action in self.actions
                ],
                "negative_attempt_count": len(self.negative_attempts),
                "source_sha256": self.source_sha256,
            }
        )


def parse_action(raw: Mapping[str, Any], index: int) -> EvidenceAction:
    if not isinstance(raw, Mapping):
        raise ContractError(f"action[{index}]_not_object")

    label = _required_text(raw, "label", index)
    role = _required_text(raw, "role", index)
    account = _required_text(raw, "account", index)
    tx_type = _required_text(raw, "tx_type", index)
    tx_id = _required_text(raw, "tx_id", index)
    subject_id = _required_text(raw, "subject_id", index)
    status = _required_text(raw, "status", index).lower()

    if status not in TERMINAL_STATUSES:
        raise ContractError(f"action[{index}].status_not_terminal:{status}")

    evidence_raw = str(raw.get("evidence_kind") or "").strip()
    if not evidence_raw:
        kind = EvidenceKind.DIRECT_TRANSACTION
    else:
        try:
            kind = EvidenceKind(evidence_raw)
        except ValueError as exc:
            raise ContractError(
                f"action[{index}].evidence_kind_unknown:{evidence_raw}"
            ) from exc

    common = {
        "index": index,
        "label": label,
        "role": role,
        "account": account,
        "tx_type": tx_type,
        "tx_id": tx_id,
        "subject_id": subject_id,
        "status": status,
    }

    if kind is EvidenceKind.INLINE_SYSTEM_TRANSITION:
        trigger_tx_id = _required_text(raw, "trigger_tx_id", index)
        trigger_height = _required_int(raw, "trigger_included_height", index)
        state_height = _required_int(raw, "state_height", index)

        if role != "system_scheduler":
            raise ContractError(f"action[{index}].inline_role_invalid:{role}")
        if account != "SYSTEM":
            raise ContractError(f"action[{index}].inline_account_invalid:{account}")
        if not trigger_tx_id.startswith("tx:"):
            raise ContractError(f"action[{index}].inline_trigger_invalid")
        expected_inline_id = f"inline:{trigger_tx_id}:{tx_type}"
        if tx_id != expected_inline_id:
            raise ContractError(
                f"action[{index}].inline_tx_id_mismatch:"
                f"expected={expected_inline_id}:actual={tx_id}"
            )
        if trigger_height <= state_height:
            raise ContractError(
                f"action[{index}].inline_height_order_invalid:"
                f"state={state_height}:trigger={trigger_height}"
            )

        return InlineSystemTransitionAction(
            **common,
            trigger_tx_id=trigger_tx_id,
            trigger_included_height=trigger_height,
            state_height=state_height,
        )

    if not tx_id.startswith("tx:"):
        raise ContractError(f"action[{index}].direct_tx_id_invalid:{tx_id}")

    if kind is EvidenceKind.ACCEPTANCE_EMBEDDED_ATTENDANCE:
        return EmbeddedAttendanceAction(**common)

    return DirectTransactionAction(**common)


def parse_transcript(path: str | Path) -> Transcript:
    source = Path(path).resolve()
    try:
        raw_bytes = source.read_bytes()
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"transcript_unreadable:{source}") from exc

    if not isinstance(obj, Mapping):
        raise ContractError("transcript_not_object")

    schema_version = obj.get("schema_version")
    if schema_version != 1:
        raise ContractError(f"transcript_schema_invalid:{schema_version}")

    freeze = str(obj.get("implementation_freeze_commit") or "").strip()
    chain_id = str(obj.get("chain_id") or "").strip()
    if len(freeze) != 40:
        raise ContractError("transcript_freeze_invalid")
    if not chain_id:
        raise ContractError("transcript_chain_id_missing")

    actions_raw = obj.get("actions")
    negatives_raw = obj.get("negative_attempts")
    if not isinstance(actions_raw, list) or not actions_raw:
        raise ContractError("transcript_actions_invalid")
    if not isinstance(negatives_raw, list):
        raise ContractError("transcript_negative_attempts_invalid")

    actions = tuple(parse_action(item, index) for index, item in enumerate(actions_raw))
    negatives: tuple[Mapping[str, Any], ...] = tuple(
        item for item in negatives_raw if isinstance(item, Mapping)
    )
    if len(negatives) != len(negatives_raw):
        raise ContractError("transcript_negative_attempt_not_object")

    return Transcript(
        schema_version=1,
        implementation_freeze_commit=freeze,
        chain_id=chain_id,
        actions=actions,
        negative_attempts=negatives,
        source_sha256=__import__("hashlib").sha256(raw_bytes).hexdigest(),
    )
