from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any

from .errors import ContractError
from .http_client import RateLimitedJsonClient
from .models import (
    DeterministicSystemReceiptAction,
    DirectTransactionAction,
    EmbeddedAttendanceAction,
    InlineSystemTransitionAction,
    TERMINAL_STATUSES,
    Transcript,
)
from .util import canonical_json_sha256


@dataclass(frozen=True)
class VerificationSummary:
    chain_id: str
    action_count: int
    direct_action_count: int
    deterministic_receipt_count: int
    embedded_action_count: int
    inline_action_count: int
    unique_status_query_count: int
    records: tuple[dict[str, Any], ...]
    request_traces: tuple[dict[str, Any], ...]

    def to_json(self) -> dict[str, Any]:
        payload = {
            "schema": "weall.m3.status-verification.v2",
            "chain_id": self.chain_id,
            "action_count": self.action_count,
            "direct_action_count": self.direct_action_count,
            "deterministic_receipt_count": self.deterministic_receipt_count,
            "embedded_action_count": self.embedded_action_count,
            "inline_action_count": self.inline_action_count,
            "unique_status_query_count": self.unique_status_query_count,
            "records": list(self.records),
            "request_traces": list(self.request_traces),
        }
        payload["verification_sha256"] = canonical_json_sha256(payload)
        return payload


def _status_path(tx_id: str) -> str:
    return "/v1/tx/status/" + urllib.parse.quote(tx_id, safe="")


def verify_transcript_statuses(
    transcript: Transcript,
    client: RateLimitedJsonClient,
) -> VerificationSummary:
    identity = client.get_json("/v1/chain/identity")
    observed_chain = str(
        identity.get("chain_id")
        or (
            identity.get("identity", {}).get("chain_id")
            if isinstance(identity.get("identity"), dict)
            else ""
        )
        or ""
    )
    if observed_chain != transcript.chain_id:
        raise ContractError(
            f"chain_id_mismatch:"
            f"expected={transcript.chain_id}:actual={observed_chain}"
        )

    cache: dict[str, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    direct_count = 0
    deterministic_receipt_count = 0
    embedded_count = 0
    inline_count = 0

    for action in transcript.actions:
        query_tx_id = action.status_query_tx_id
        if query_tx_id not in cache:
            cache[query_tx_id] = client.get_json(_status_path(query_tx_id))
        status = cache[query_tx_id]
        phase = str(status.get("status") or status.get("phase") or "").lower()
        if phase not in TERMINAL_STATUSES:
            raise ContractError(
                f"action_not_terminal:index={action.index}:"
                f"query_tx_id={query_tx_id}:status={phase}"
            )

        if isinstance(action, InlineSystemTransitionAction):
            inline_count += 1
            height = int(status.get("height") or 0)
            if height != action.trigger_included_height:
                raise ContractError(
                    f"inline_trigger_height_mismatch:index={action.index}:"
                    f"expected={action.trigger_included_height}:actual={height}"
                )
            records.append(
                {
                    "index": action.index,
                    "label": action.label,
                    "evidence_kind": action.evidence_kind.value,
                    "action_tx_id": action.tx_id,
                    "queried_tx_id": action.trigger_tx_id,
                    "action_tx_type": action.tx_type,
                    "action_account": action.account,
                    "status": phase,
                    "height": height,
                }
            )
            continue

        tx_type = str(status.get("tx_type") or "")
        signer = str(status.get("signer") or "")
        if tx_type != action.tx_type:
            raise ContractError(
                f"tx_type_mismatch:index={action.index}:"
                f"expected={action.tx_type}:actual={tx_type}"
            )
        if signer != action.account:
            raise ContractError(
                f"signer_mismatch:index={action.index}:"
                f"expected={action.account}:actual={signer}"
            )

        if isinstance(action, DeterministicSystemReceiptAction):
            deterministic_receipt_count += 1
            actual_height = int(status.get("height") or 0)
            if actual_height != action.state_height:
                raise ContractError(
                    f"system_receipt_height_mismatch:index={action.index}:"
                    f"expected={action.state_height}:actual={actual_height}"
                )
        elif isinstance(action, EmbeddedAttendanceAction):
            embedded_count += 1
        elif isinstance(action, DirectTransactionAction):
            direct_count += 1
        else:
            raise ContractError(f"unsupported_action_type:index={action.index}")

        records.append(
            {
                "index": action.index,
                "label": action.label,
                "evidence_kind": action.evidence_kind.value,
                "action_tx_id": action.tx_id,
                "queried_tx_id": query_tx_id,
                "action_tx_type": tx_type,
                "action_account": signer,
                "status": phase,
                "height": int(status.get("height") or 0),
            }
        )

    return VerificationSummary(
        chain_id=observed_chain,
        action_count=len(transcript.actions),
        direct_action_count=direct_count,
        deterministic_receipt_count=deterministic_receipt_count,
        embedded_action_count=embedded_count,
        inline_action_count=inline_count,
        unique_status_query_count=len(cache),
        records=tuple(records),
        request_traces=tuple(trace.to_json() for trace in client.traces),
    )
