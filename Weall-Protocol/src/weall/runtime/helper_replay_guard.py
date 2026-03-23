from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Deque, Mapping, Sequence

from weall.runtime.helper_certificates import HelperExecutionCertificate
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator

Json = dict[str, Any]


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


def _certificate_fingerprint(cert: HelperExecutionCertificate) -> str:
    return _sha256_hex(cert.to_json())


@dataclass
class HelperRateBudget:
    per_helper_per_window: int = 64
    per_plan_total: int = 1024
    window_ms: int = 5_000


@dataclass
class ReplayDecision:
    accepted: bool
    reason: str
    helper_id: str
    plan_id: str
    lane_id: str


@dataclass(frozen=True, slots=True)
class HelperReplayOutcome:
    accepted: bool
    code: str
    lane_id: str
    fingerprint: str


class HelperReplayGuard:
    def __init__(
        self,
        *,
        orchestrator: HelperProposalOrchestrator | None = None,
        journal: HelperLaneJournal | None = None,
        budget: HelperRateBudget | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.journal = journal
        self.budget = budget if budget is not None else HelperRateBudget()

        # budget/rate-limit mode state
        self._seen_receipt_ids: set[str] = set()
        self._plan_totals: dict[str, int] = defaultdict(int)
        self._helper_windows: dict[tuple[str, str], Deque[int]] = defaultdict(deque)
        self._conflicts: dict[tuple[str, str, str], str] = {}

        # orchestrator/replay mode state
        self.plan_id = str(orchestrator.plan_id or "") if orchestrator is not None else ""
        self._resolved_fingerprints: dict[str, str] = {}
        self._resolved_modes: dict[str, str] = {}

        if self.orchestrator is not None and self.journal is not None:
            self._recover_from_journal()

    def _trim(self, timestamps: Deque[int], *, now_ms: int) -> None:
        cutoff = now_ms - self.budget.window_ms
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

    # ---------- budget/plan-window mode ----------
    def observe_artifact(self, artifact: Mapping[str, Any], *, now_ms: int) -> ReplayDecision:
        receipt_id = str(artifact.get("receipt_id") or artifact.get("certificate_id") or "")
        helper_id = str(artifact.get("helper_id") or "")
        plan_id = str(artifact.get("plan_id") or "")
        lane_id = str(artifact.get("lane_id") or "")
        descriptor_hash = str(artifact.get("descriptor_hash") or "")
        if not helper_id or not plan_id or not lane_id:
            return ReplayDecision(False, "missing_identity_fields", helper_id, plan_id, lane_id)
        if receipt_id and receipt_id in self._seen_receipt_ids:
            return ReplayDecision(False, "duplicate_artifact", helper_id, plan_id, lane_id)

        window = self._helper_windows[(plan_id, helper_id)]
        self._trim(window, now_ms=now_ms)
        if len(window) >= self.budget.per_helper_per_window:
            return ReplayDecision(False, "helper_rate_budget_exceeded", helper_id, plan_id, lane_id)
        if self._plan_totals[plan_id] >= self.budget.per_plan_total:
            return ReplayDecision(False, "plan_total_budget_exceeded", helper_id, plan_id, lane_id)

        conflict_key = (plan_id, helper_id, lane_id)
        existing_hash = self._conflicts.get(conflict_key)
        if existing_hash is None and descriptor_hash:
            self._conflicts[conflict_key] = descriptor_hash
        elif existing_hash is not None and descriptor_hash and existing_hash != descriptor_hash:
            return ReplayDecision(False, "conflicting_artifact_for_same_helper_lane", helper_id, plan_id, lane_id)

        if receipt_id:
            self._seen_receipt_ids.add(receipt_id)
        window.append(now_ms)
        self._plan_totals[plan_id] += 1
        return ReplayDecision(True, "accepted", helper_id, plan_id, lane_id)

    # ---------- orchestrator/replay mode ----------
    def _recover_from_journal(self) -> None:
        state = self.journal.load_resolution_state()
        journal_plan_id = str(state.get("plan_id") or "")
        if journal_plan_id and self.plan_id and journal_plan_id != self.plan_id:
            return
        for record in self.journal.load():
            kind = str(record.get("kind") or "")
            if kind == "helper_finalized":
                lane_id = str(record.get("lane_id") or "")
                cert_obj = record.get("certificate")
                if not lane_id or not isinstance(cert_obj, dict):
                    continue
                try:
                    cert_obj = dict(cert_obj)
                    tx_ids = cert_obj.get("tx_ids")
                    if isinstance(tx_ids, list):
                        cert_obj["tx_ids"] = tuple(str(x) for x in tx_ids)
                    cert = HelperExecutionCertificate(**cert_obj)
                except Exception:
                    continue
                if self.plan_id and str(cert.plan_id or "") not in {"", self.plan_id}:
                    continue
                self._resolved_fingerprints[lane_id] = _certificate_fingerprint(cert)
                self._resolved_modes[lane_id] = "helper"
            elif kind == "fallback_finalized":
                lane_id = str(record.get("lane_id") or "")
                helper_id = str(record.get("helper_id") or "")
                plan_id = str(record.get("plan_id") or "")
                if not lane_id:
                    continue
                if self.plan_id and plan_id and plan_id != self.plan_id:
                    continue
                self._resolved_fingerprints[lane_id] = _sha256_hex(
                    {"lane_id": lane_id, "helper_id": helper_id, "mode": "fallback", "plan_id": plan_id}
                )
                self._resolved_modes[lane_id] = "fallback"

    def resolution_outcome_for_lane(self, lane_id: str) -> HelperReplayOutcome | None:
        lane_id2 = str(lane_id or "")
        fingerprint = self._resolved_fingerprints.get(lane_id2)
        mode = self._resolved_modes.get(lane_id2)
        if not fingerprint or not mode:
            return None
        return HelperReplayOutcome(accepted=True, code=f"resolved:{mode}", lane_id=lane_id2, fingerprint=fingerprint)

    def ingest_certificate(self, *, cert: HelperExecutionCertificate, peer_id: str) -> HelperReplayOutcome:
        if self.orchestrator is None:
            raise TypeError("HelperReplayGuard.ingest_certificate requires orchestrator mode")
        lane_id = str(cert.lane_id or "")
        fingerprint = _certificate_fingerprint(cert)
        if self.plan_id and str(cert.plan_id or "") not in {"", self.plan_id}:
            return HelperReplayOutcome(accepted=False, code="plan_id_mismatch", lane_id=lane_id, fingerprint=fingerprint)

        existing_fp = self._resolved_fingerprints.get(lane_id)
        existing_mode = self._resolved_modes.get(lane_id)
        if existing_fp is not None:
            if existing_mode == "fallback":
                return HelperReplayOutcome(
                    accepted=False, code="lane_already_resolved_fallback", lane_id=lane_id, fingerprint=fingerprint
                )
            if existing_fp == fingerprint:
                return HelperReplayOutcome(accepted=False, code="duplicate_replay", lane_id=lane_id, fingerprint=fingerprint)
            return HelperReplayOutcome(accepted=False, code="conflicting_replay", lane_id=lane_id, fingerprint=fingerprint)

        status = self.orchestrator.ingest_certificate(cert=cert, peer_id=peer_id)
        if not status.accepted:
            return HelperReplayOutcome(accepted=False, code=str(status.code), lane_id=lane_id, fingerprint=fingerprint)

        self._resolved_fingerprints[lane_id] = fingerprint
        self._resolved_modes[lane_id] = "helper"
        return HelperReplayOutcome(accepted=True, code="accepted", lane_id=lane_id, fingerprint=fingerprint)

    def ingest_certificates_batch(
        self,
        *,
        certificates: Sequence[tuple[HelperExecutionCertificate, str]],
    ) -> tuple[HelperReplayOutcome, ...]:
        ordered: list[tuple[str, str, str, HelperExecutionCertificate]] = []
        for cert, peer_id in tuple(certificates or ()):
            lane_id = str(getattr(cert, "lane_id", "") or "")
            fingerprint = _certificate_fingerprint(cert)
            ordered.append((lane_id, fingerprint, str(peer_id or ""), cert))
        ordered.sort(key=lambda item: (item[0], item[1], item[2]))
        outcomes = [self.ingest_certificate(cert=cert, peer_id=peer_id) for _, _, peer_id, cert in ordered]
        return tuple(outcomes)

    def finalize_timeouts(self, *, now_ms: int) -> tuple[HelperReplayOutcome, ...]:
        if self.orchestrator is None:
            raise TypeError("HelperReplayGuard.finalize_timeouts requires orchestrator mode")
        finalized = self.orchestrator.finalize_timeouts(now_ms=now_ms)
        out: list[HelperReplayOutcome] = []
        for resolution in finalized:
            lane_id = str(resolution.lane_id)
            helper_id = str(resolution.helper_id)
            fingerprint = _sha256_hex(
                {"lane_id": lane_id, "helper_id": helper_id, "mode": "fallback", "plan_id": self.plan_id}
            )
            self._resolved_fingerprints[lane_id] = fingerprint
            self._resolved_modes[lane_id] = "fallback"
            out.append(HelperReplayOutcome(accepted=True, code="fallback_finalized", lane_id=lane_id, fingerprint=fingerprint))
        out.sort(key=lambda item: item.lane_id)
        return tuple(out)

    def resolved_lanes(self) -> tuple[str, ...]:
        lanes = sorted(self._resolved_fingerprints.keys())
        return tuple(lanes)
