from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    verify_helper_certificate_signature,
)
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.parallel_execution import (
    LanePlan,
    canonical_lane_plan_fingerprint,
    verify_helper_certificate,
)
from weall.runtime.validator_execution_model import verify_validator_execution_manifest

Json = dict[str, Any]


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


def certificate_fingerprint(cert: HelperExecutionCertificate) -> str:
    return _sha256_hex(cert.to_json())


@dataclass(frozen=True, slots=True)
class HelperDispatchContext:
    chain_id: str
    block_height: int
    view: int
    leader_id: str
    validator_epoch: int
    validator_set_hash: str
    manifest_hash: str = ""
    coordinator_pubkey: str = ""
    manifest_signature: str = ""
    manifest_signed: bool = False
    manifest_signature_required: bool = False
    manifest_payload: Json | None = None
    strict_helper_certificate_consistency: bool = False
    strict_helper_receipts_root: bool = False
    strict_helper_state_delta_hash: bool = False
    plan_id: str = ""


@dataclass(frozen=True, slots=True)
class HelperDispatchStatus:
    accepted: bool
    code: str
    lane_id: str
    helper_id: str


@dataclass(frozen=True, slots=True)
class HelperBudgetDecision:
    accepted: bool
    reason: str
    helper_id: str
    plan_id: str
    lane_id: str


class _DefaultBudget:
    def __init__(self) -> None:
        self.per_helper_per_window = 64
        self.per_plan_total = 1024
        self.window_ms = 5000


class HelperCertificateStore:
    def __init__(
        self,
        *,
        context: HelperDispatchContext | None = None,
        lane_plans: tuple[LanePlan, ...] = (),
        helper_pubkeys: dict[str, str] | None = None,
        journal: HelperLaneJournal | None = None,
        helper_timeout_ms: int | None = None,
        max_inflight_lanes: int | None = None,
        budget: HelperRateBudget | None = None,
        plan_timeout_ms: int | None = None,
    ) -> None:
        self.context = context
        self.lane_plans = {plan.lane_id: plan for plan in lane_plans}
        self.helper_pubkeys = {str(k): str(v) for k, v in dict(helper_pubkeys or {}).items()}
        self.journal = journal
        self.helper_timeout_ms = int(helper_timeout_ms if helper_timeout_ms is not None else (plan_timeout_ms if plan_timeout_ms is not None else 5000))
        self.max_inflight_lanes = max(1, int(max_inflight_lanes or max(len(tuple(lane_plans or ())), 1)))
        self.current_plan_id = ""
        if context is not None:
            self.current_plan_id = str(context.plan_id or canonical_lane_plan_fingerprint(tuple(lane_plans or ())))
        self._certs: dict[str, HelperExecutionCertificate] = {}
        self._seen_keys: set[tuple[str, str, str]] = set()
        self._request_started_ms: dict[str, int] = {}
        self._closed_lanes: set[str] = set()

        self._budget = budget if budget is not None else _DefaultBudget()
        self._plan_window_opened_ms: dict[str, int] = {}
        self._plan_totals: dict[str, int] = {}
        self._helper_windows: dict[tuple[str, str], list[int]] = {}
        self._budget_seen_receipts: set[str] = set()
        self._budget_conflicts: dict[tuple[str, str, str], str] = {}

        if self.journal is not None:
            self._recover_from_journal()

    def _recover_from_journal(self) -> None:
        state = self.journal.load_resolution_state()
        journal_plan_id = str(state.get("plan_id") or "")
        if journal_plan_id and self.current_plan_id and journal_plan_id != self.current_plan_id:
            return
        for record in self.journal.load():
            kind = str(record.get("kind") or "")
            if kind == "request_started":
                lane_id = str(record.get("lane_id") or "")
                started_ms = int(record.get("started_ms") or 0)
                if lane_id:
                    self._request_started_ms[lane_id] = started_ms
            elif kind == "request_closed":
                lane_id = str(record.get("lane_id") or "")
                if lane_id:
                    self._closed_lanes.add(lane_id)
            elif kind in {"certificate_accepted", "helper_finalized"}:
                cert_obj = record.get("certificate")
                if not isinstance(cert_obj, dict):
                    continue
                try:
                    cert_obj = dict(cert_obj)
                    tx_ids = cert_obj.get("tx_ids")
                    if isinstance(tx_ids, list):
                        cert_obj["tx_ids"] = tuple(str(x) for x in tx_ids)
                    cert = HelperExecutionCertificate(**cert_obj)
                except Exception:
                    continue
                if self.current_plan_id and str(cert.plan_id or "") not in {"", self.current_plan_id}:
                    continue
                lane_id = str(cert.lane_id)
                if not lane_id:
                    continue
                existing = self._certs.get(lane_id)
                if existing is not None and existing.to_json() != cert.to_json():
                    continue
                self._certs[lane_id] = cert
                self._closed_lanes.add(lane_id)
                self._seen_keys.add((lane_id, str(cert.helper_id), str(cert.helper_signature)))

    def _same_certificate(self, left: HelperExecutionCertificate, right: HelperExecutionCertificate) -> bool:
        return left.to_json() == right.to_json()

    def _trim_budget_window(self, timestamps: list[int], *, now_ms: int) -> None:
        cutoff = int(now_ms) - int(self._budget.window_ms)
        while timestamps and int(timestamps[0]) < cutoff:
            timestamps.pop(0)

    def open_plan_window(self, *, plan_id: str, now_ms: int) -> None:
        plan_id2 = str(plan_id or "")
        if not plan_id2:
            return
        self.current_plan_id = plan_id2
        self._plan_window_opened_ms[plan_id2] = int(now_ms)
        self._plan_totals.setdefault(plan_id2, 0)

    def _accept_budget_artifact(self, cert: dict[str, Any], *, now_ms: int) -> HelperBudgetDecision:
        helper_id = str(cert.get("helper_id") or "")
        plan_id = str(cert.get("plan_id") or "")
        lane_id = str(cert.get("lane_id") or "")
        descriptor_hash = str(cert.get("descriptor_hash") or "")
        receipt_id = str(cert.get("receipt_id") or cert.get("certificate_id") or "")
        if not helper_id or not plan_id or not lane_id:
            return HelperBudgetDecision(False, "missing_identity_fields", helper_id, plan_id, lane_id)
        opened_ms = self._plan_window_opened_ms.get(plan_id)
        if opened_ms is None:
            return HelperBudgetDecision(False, "plan_window_not_started", helper_id, plan_id, lane_id)
        if int(now_ms) - int(opened_ms) >= self.helper_timeout_ms:
            return HelperBudgetDecision(False, "plan_window_closed", helper_id, plan_id, lane_id)
        if receipt_id and receipt_id in self._budget_seen_receipts:
            return HelperBudgetDecision(False, "duplicate_artifact", helper_id, plan_id, lane_id)

        key = (plan_id, helper_id)
        window = self._helper_windows.setdefault(key, [])
        self._trim_budget_window(window, now_ms=now_ms)
        if len(window) >= int(self._budget.per_helper_per_window):
            return HelperBudgetDecision(False, "helper_rate_budget_exceeded", helper_id, plan_id, lane_id)
        if int(self._plan_totals.get(plan_id, 0)) >= int(self._budget.per_plan_total):
            return HelperBudgetDecision(False, "plan_total_budget_exceeded", helper_id, plan_id, lane_id)

        conflict_key = (plan_id, helper_id, lane_id)
        existing_hash = self._budget_conflicts.get(conflict_key)
        if existing_hash is None and descriptor_hash:
            self._budget_conflicts[conflict_key] = descriptor_hash
        elif existing_hash is not None and descriptor_hash and existing_hash != descriptor_hash:
            return HelperBudgetDecision(False, "conflicting_artifact_for_same_helper_lane", helper_id, plan_id, lane_id)

        if receipt_id:
            self._budget_seen_receipts.add(receipt_id)
        window.append(int(now_ms))
        self._plan_totals[plan_id] = int(self._plan_totals.get(plan_id, 0)) + 1
        return HelperBudgetDecision(True, "accepted", helper_id, plan_id, lane_id)

    def accept_certificate(self, cert: dict[str, Any], *, now_ms: int) -> HelperBudgetDecision:
        return self._accept_budget_artifact(dict(cert), now_ms=now_ms)

    def start_request(self, *, lane_id: str, started_ms: int) -> None:
        lane_id2 = str(lane_id or "")
        if not lane_id2:
            return
        if lane_id2 not in self._request_started_ms and len(self.inflight_lanes()) >= self.max_inflight_lanes:
            return
        if lane_id2 in self._closed_lanes:
            self._closed_lanes.discard(lane_id2)
        self._request_started_ms[lane_id2] = int(started_ms)
        if self.journal is not None:
            self.journal.append({"kind": "request_started", "lane_id": lane_id2, "started_ms": int(started_ms), "plan_id": self.current_plan_id})

    def accepted_certificates(self) -> dict[str, HelperExecutionCertificate]:
        return dict(self._certs)

    def inflight_lanes(self) -> tuple[str, ...]:
        active = [
            lane_id
            for lane_id in self._request_started_ms.keys()
            if lane_id not in self._closed_lanes and lane_id not in self._certs
        ]
        active.sort()
        return tuple(active)

    def close_request(self, *, lane_id: str, reason: str = "closed") -> None:
        lane_id2 = str(lane_id or "")
        if not lane_id2:
            return
        self._closed_lanes.add(lane_id2)
        if self.journal is not None:
            self.journal.append({"kind": "request_closed", "lane_id": lane_id2, "reason": str(reason or "closed"), "plan_id": self.current_plan_id})

    def request_window_status(self, *, lane_id: str, now_ms: int | None = None) -> str:
        lane_id2 = str(lane_id or "")
        if not lane_id2:
            return "missing_lane"
        if lane_id2 in self._closed_lanes:
            return "closed"
        started_ms = self._request_started_ms.get(lane_id2)
        if started_ms is None:
            if self._request_started_ms or self._closed_lanes:
                return "not_started"
            return "implicit_open"
        if now_ms is not None and int(now_ms) - int(started_ms) >= self.helper_timeout_ms:
            return "expired"
        return "open"

    def timed_out_lanes(self, *, now_ms: int) -> tuple[str, ...]:
        out: list[str] = []
        for lane_id, started_ms in self._request_started_ms.items():
            if lane_id in self._certs or lane_id in self._closed_lanes:
                continue
            if int(now_ms) - int(started_ms) >= self.helper_timeout_ms:
                out.append(lane_id)
        out.sort()
        return tuple(out)

    def ingest_certificate(self, *, cert: HelperExecutionCertificate, peer_id: str, now_ms: int | None = None) -> HelperDispatchStatus:
        lane_id = str(cert.lane_id or "")
        helper_id = str(cert.helper_id or "")
        fingerprint = certificate_fingerprint(cert)

        existing = self._certs.get(lane_id)
        if existing is not None:
            if self._same_certificate(existing, cert):
                if self.journal is not None:
                    self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="duplicate_certificate")
                return HelperDispatchStatus(False, "duplicate_certificate", lane_id, helper_id)
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="conflicting_certificate")
            return HelperDispatchStatus(False, "conflicting_certificate", lane_id, helper_id)

        seen_key = (lane_id, helper_id, str(cert.helper_signature or ""))
        if seen_key in self._seen_keys:
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="duplicate_certificate")
            return HelperDispatchStatus(False, "duplicate_certificate", lane_id, helper_id)
        self._seen_keys.add(seen_key)

        window_state = self.request_window_status(lane_id=lane_id, now_ms=now_ms)
        if window_state == "not_started":
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="request_not_started")
            return HelperDispatchStatus(False, "request_not_started", lane_id, helper_id)
        if window_state == "closed":
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="request_window_closed")
            return HelperDispatchStatus(False, "request_window_closed", lane_id, helper_id)
        if window_state == "expired":
            self.close_request(lane_id=lane_id, reason="timeout")
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="request_window_closed")
            return HelperDispatchStatus(False, "request_window_closed", lane_id, helper_id)
        lane_plan = self.lane_plans.get(lane_id)
        if lane_plan is None:
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="unknown_lane")
            return HelperDispatchStatus(False, "unknown_lane", lane_id, helper_id)
        if self.context is None:
            return HelperDispatchStatus(False, "missing_context", lane_id, helper_id)
        if bool(self.context.manifest_signature_required):
            if not isinstance(self.context.manifest_payload, dict):
                return HelperDispatchStatus(False, "missing_manifest_payload", lane_id, helper_id)
            if not verify_validator_execution_manifest(self.context.manifest_payload, expected_pubkey=str(self.context.coordinator_pubkey or "")):
                return HelperDispatchStatus(False, "invalid_manifest_signature", lane_id, helper_id)
        elif str(self.context.manifest_signature or "") or str(self.context.coordinator_pubkey or ""):
            if not isinstance(self.context.manifest_payload, dict) or not verify_validator_execution_manifest(self.context.manifest_payload, expected_pubkey=str(self.context.coordinator_pubkey or "")):
                return HelperDispatchStatus(False, "invalid_manifest_signature", lane_id, helper_id)
        if str(peer_id or "") != helper_id:
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="wrong_peer")
            return HelperDispatchStatus(False, "wrong_peer", lane_id, helper_id)
        if helper_id != str(lane_plan.helper_id or ""):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="wrong_helper")
            return HelperDispatchStatus(False, "wrong_helper", lane_id, helper_id)
        if str(cert.chain_id) != str(self.context.chain_id):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="chain_id_mismatch")
            return HelperDispatchStatus(False, "chain_id_mismatch", lane_id, helper_id)
        if str(cert.leader_id) != str(self.context.leader_id):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="leader_mismatch")
            return HelperDispatchStatus(False, "leader_mismatch", lane_id, helper_id)
        if int(cert.view) != int(self.context.view) or int(cert.block_height) != int(self.context.block_height):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="stale_certificate")
            return HelperDispatchStatus(False, "stale_certificate", lane_id, helper_id)
        if int(cert.validator_epoch) != int(self.context.validator_epoch):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="epoch_mismatch")
            return HelperDispatchStatus(False, "epoch_mismatch", lane_id, helper_id)
        if str(cert.validator_set_hash) != str(self.context.validator_set_hash):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="validator_set_hash_mismatch")
            return HelperDispatchStatus(False, "validator_set_hash_mismatch", lane_id, helper_id)
        if self.current_plan_id and str(cert.plan_id or "") not in {"", self.current_plan_id}:
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="plan_id_mismatch")
            return HelperDispatchStatus(False, "plan_id_mismatch", lane_id, helper_id)
        if str(self.context.manifest_hash or "") and str(cert.manifest_hash or "") != str(self.context.manifest_hash):
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="manifest_hash_mismatch")
            return HelperDispatchStatus(False, "manifest_hash_mismatch", lane_id, helper_id)

        helper_pubkey = self.helper_pubkeys.get(helper_id, "")
        if helper_pubkey:
            if not verify_helper_certificate_signature(cert, helper_pubkey=helper_pubkey):
                if self.journal is not None:
                    self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason="bad_signature")
                return HelperDispatchStatus(False, "bad_signature", lane_id, helper_id)

        ok, reason = verify_helper_certificate(
            cert=cert,
            lane_plan=lane_plan,
            expected_helper_id=str(lane_plan.helper_id or ""),
            chain_id=self.context.chain_id,
            block_height=self.context.block_height,
            view=self.context.view,
            leader_id=self.context.leader_id,
            validator_epoch=self.context.validator_epoch,
            validator_set_hash=self.context.validator_set_hash,
            manifest_hash=self.context.manifest_hash,
            require_internal_consistency=bool(self.context.strict_helper_certificate_consistency),
            plan_id=self.current_plan_id,
        )
        if not ok:
            if self.journal is not None:
                self.journal.append_receipt_reject(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint, reason=str(reason or "invalid_certificate"))
            return HelperDispatchStatus(False, str(reason or "invalid_certificate"), lane_id, helper_id)

        self._certs[lane_id] = cert
        self.close_request(lane_id=lane_id, reason="accepted")
        if self.journal is not None:
            self.journal.append_receipt_accept(plan_id=self.current_plan_id, lane_id=lane_id, helper_id=helper_id, receipt_fingerprint=fingerprint)
            self.journal.append({"kind": "certificate_accepted", "lane_id": lane_id, "helper_id": helper_id, "certificate": cert.to_json(), "plan_id": self.current_plan_id})
        return HelperDispatchStatus(True, "accepted", lane_id, helper_id)
