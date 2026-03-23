from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from weall.crypto.sig import sign_ed25519, verify_ed25519_signature
from weall.runtime.parallel_execution import LanePlan

Json = dict[str, Any]


def _canon_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class LaneHelperBinding:
    lane_id: str
    helper_id: str
    tx_ids: tuple[str, ...] = field(default_factory=tuple)
    namespace_prefixes: tuple[str, ...] = field(default_factory=tuple)
    helper_candidates: tuple[str, ...] = field(default_factory=tuple)
    original_helper_id: str = ""
    rerouted_from_helper_id: str = ""
    routing_mode: str = "helper"
    lane_class: str = "serial"
    lane_tx_types: tuple[str, ...] = field(default_factory=tuple)
    capability_restricted: bool = False
    lane_cost_units: int = 1
    helper_capacity_units: int = 0

    def to_json(self) -> Json:
        return {
            "lane_id": self.lane_id,
            "helper_id": self.helper_id,
            "tx_ids": list(self.tx_ids),
            "namespace_prefixes": list(self.namespace_prefixes),
            "helper_candidates": list(self.helper_candidates),
            "original_helper_id": self.original_helper_id,
            "rerouted_from_helper_id": self.rerouted_from_helper_id,
            "routing_mode": self.routing_mode,
            "lane_class": self.lane_class,
            "lane_tx_types": list(self.lane_tx_types),
            "capability_restricted": bool(self.capability_restricted),
            "lane_cost_units": int(self.lane_cost_units),
            "helper_capacity_units": int(self.helper_capacity_units),
        }


@dataclass(frozen=True, slots=True)
class ValidatorExecutionManifest:
    chain_id: str
    block_height: int
    view: int
    leader_id: str
    coordinator_id: str
    validator_epoch: int
    validator_set_hash: str
    validators: tuple[str, ...] = field(default_factory=tuple)
    helper_bindings: tuple[LaneHelperBinding, ...] = field(default_factory=tuple)
    serial_lane_ids: tuple[str, ...] = field(default_factory=tuple)
    coordinator_pubkey: str = ""
    manifest_signature: str = ""
    manifest_signed: bool = False

    def signing_payload(self) -> Json:
        return {
            "chain_id": self.chain_id,
            "block_height": int(self.block_height),
            "view": int(self.view),
            "leader_id": self.leader_id,
            "coordinator_id": self.coordinator_id,
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
            "validators": list(self.validators),
            "helper_bindings": [binding.to_json() for binding in self.helper_bindings],
            "serial_lane_ids": list(self.serial_lane_ids),
            "coordinator_pubkey": self.coordinator_pubkey,
        }

    def to_payload(self) -> Json:
        payload = self.signing_payload()
        payload["manifest_signature"] = self.manifest_signature
        payload["manifest_signed"] = bool(self.manifest_signed)
        return payload

    def manifest_hash(self) -> str:
        return hashlib.sha256(_canon_json(self.signing_payload())).hexdigest()

    def helper_ids(self) -> tuple[str, ...]:
        return tuple(sorted({binding.helper_id for binding in self.helper_bindings if binding.helper_id}))

    def role_for_node(self, node_id: str) -> str:
        nid = str(node_id or "")
        if not nid:
            return "observer"
        if nid == self.coordinator_id:
            return "coordinator"
        if any(binding.helper_id == nid for binding in self.helper_bindings):
            return "helper"
        if nid in self.validators:
            return "validator_observer"
        return "observer"

    def verify_signature(self, *, expected_pubkey: str | None = None) -> bool:
        required_pubkey = str(expected_pubkey or self.coordinator_pubkey or "")
        if not required_pubkey or not str(self.manifest_signature or ""):
            return False
        try:
            return verify_ed25519_signature(
                message=_canon_json(self.signing_payload()),
                sig=str(self.manifest_signature),
                pubkey=required_pubkey,
            )
        except Exception:
            return False

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "ValidatorExecutionManifest":
        bindings_obj = payload.get("helper_bindings")
        bindings: list[LaneHelperBinding] = []
        if isinstance(bindings_obj, Sequence) and not isinstance(bindings_obj, (str, bytes, bytearray)):
            for item in bindings_obj:
                if not isinstance(item, Mapping):
                    continue
                tx_ids = item.get("tx_ids")
                prefixes = item.get("namespace_prefixes")
                candidates = item.get("helper_candidates")
                bindings.append(
                    LaneHelperBinding(
                        lane_id=str(item.get("lane_id") or ""),
                        helper_id=str(item.get("helper_id") or ""),
                        tx_ids=tuple(str(x) for x in list(tx_ids or [])),
                        namespace_prefixes=tuple(str(x) for x in list(prefixes or [])),
                        helper_candidates=tuple(str(x) for x in list(candidates or [])),
                        original_helper_id=str(item.get("original_helper_id") or ""),
                        rerouted_from_helper_id=str(item.get("rerouted_from_helper_id") or ""),
                        routing_mode=str(item.get("routing_mode") or "helper"),
                        lane_class=str(item.get("lane_class") or "serial"),
                        lane_tx_types=tuple(str(x) for x in list(item.get("lane_tx_types") or [])),
                        capability_restricted=bool(item.get("capability_restricted", False)),
                        lane_cost_units=int(item.get("lane_cost_units") or 1),
                        helper_capacity_units=int(item.get("helper_capacity_units") or 0),
                    )
                )
        return cls(
            chain_id=str(payload.get("chain_id") or ""),
            block_height=int(payload.get("block_height") or 0),
            view=int(payload.get("view") or 0),
            leader_id=str(payload.get("leader_id") or ""),
            coordinator_id=str(payload.get("coordinator_id") or ""),
            validator_epoch=int(payload.get("validator_epoch") or 0),
            validator_set_hash=str(payload.get("validator_set_hash") or ""),
            validators=tuple(str(v) for v in list(payload.get("validators") or [])),
            helper_bindings=tuple(bindings),
            serial_lane_ids=tuple(str(x) for x in list(payload.get("serial_lane_ids") or [])),
            coordinator_pubkey=str(payload.get("coordinator_pubkey") or ""),
            manifest_signature=str(payload.get("manifest_signature") or ""),
            manifest_signed=bool(payload.get("manifest_signed", False)),
        )


def sign_validator_execution_manifest(
    manifest: ValidatorExecutionManifest,
    *,
    coordinator_pubkey: str,
    coordinator_privkey: str,
) -> ValidatorExecutionManifest:
    payload = _canon_json(manifest.signing_payload())
    signature = sign_ed25519(message=payload, privkey=str(coordinator_privkey), encoding="hex")
    return ValidatorExecutionManifest(
        chain_id=manifest.chain_id,
        block_height=int(manifest.block_height),
        view=int(manifest.view),
        leader_id=manifest.leader_id,
        coordinator_id=manifest.coordinator_id,
        validator_epoch=int(manifest.validator_epoch),
        validator_set_hash=manifest.validator_set_hash,
        validators=tuple(manifest.validators),
        helper_bindings=tuple(manifest.helper_bindings),
        serial_lane_ids=tuple(manifest.serial_lane_ids),
        coordinator_pubkey=str(coordinator_pubkey or ""),
        manifest_signature=str(signature or ""),
        manifest_signed=True,
    )


def verify_validator_execution_manifest(
    manifest: ValidatorExecutionManifest | Mapping[str, Any],
    *,
    expected_pubkey: str | None = None,
) -> bool:
    normalized = manifest if isinstance(manifest, ValidatorExecutionManifest) else ValidatorExecutionManifest.from_json(manifest)
    if not normalized.manifest_signed:
        return False
    return normalized.verify_signature(expected_pubkey=expected_pubkey)


def build_validator_execution_manifest(
    *,
    chain_id: str,
    block_height: int,
    view: int,
    leader_id: str,
    validator_epoch: int,
    validator_set_hash: str,
    validators: Sequence[str],
    lane_plans: Sequence[LanePlan],
    coordinator_pubkey: str = "",
    manifest_signature: str = "",
    manifest_signed: bool = False,
) -> ValidatorExecutionManifest:
    normalized_validators = tuple(sorted({str(v) for v in list(validators or []) if str(v)}))
    bindings: list[LaneHelperBinding] = []
    serial_lane_ids: list[str] = []
    for lane in list(lane_plans or []):
        helper_id = str(lane.helper_id or "")
        if helper_id:
            bindings.append(
                LaneHelperBinding(
                    lane_id=str(lane.lane_id),
                    helper_id=helper_id,
                    tx_ids=tuple(str(tx_id) for tx_id in lane.tx_ids),
                    namespace_prefixes=tuple(str(prefix) for prefix in lane.namespace_prefixes),
                    helper_candidates=tuple(str(v) for v in getattr(lane, "helper_candidates", ()) or ()),
                    original_helper_id=str(getattr(lane, "original_helper_id", "") or ""),
                    rerouted_from_helper_id=str(getattr(lane, "rerouted_from_helper_id", "") or ""),
                    routing_mode=str(getattr(lane, "routing_mode", "helper") or "helper"),
                    lane_class=str(getattr(lane, "lane_class", "serial") or "serial"),
                    lane_tx_types=tuple(str(v) for v in (getattr(lane, "lane_tx_types", ()) or ())),
                    capability_restricted=bool(getattr(lane, "capability_restricted", False)),
                    lane_cost_units=int(getattr(lane, "lane_cost_units", 1) or 1),
                    helper_capacity_units=int(getattr(lane, "helper_capacity_units", 0) or 0),
                )
            )
        else:
            serial_lane_ids.append(str(lane.lane_id))
    bindings.sort(key=lambda item: (item.lane_id, item.helper_id, item.tx_ids))
    serial_lane_ids = sorted({lane_id for lane_id in serial_lane_ids if lane_id})
    coordinator_id = str(leader_id or "")
    return ValidatorExecutionManifest(
        chain_id=str(chain_id or ""),
        block_height=int(block_height),
        view=int(view),
        leader_id=str(leader_id or ""),
        coordinator_id=coordinator_id,
        validator_epoch=int(validator_epoch),
        validator_set_hash=str(validator_set_hash or ""),
        validators=normalized_validators,
        helper_bindings=tuple(bindings),
        serial_lane_ids=tuple(serial_lane_ids),
        coordinator_pubkey=str(coordinator_pubkey or ""),
        manifest_signature=str(manifest_signature or ""),
        manifest_signed=bool(manifest_signed),
    )


def validator_execution_summary(*, manifest: ValidatorExecutionManifest, local_node_id: str) -> Json:
    helper_ids = manifest.helper_ids()
    total_lane_cost_units = sum(int(getattr(binding, "lane_cost_units", 1) or 1) for binding in manifest.helper_bindings)
    return {
        "model": "coordinator_helper",
        "manifest_hash": manifest.manifest_hash(),
        "manifest_signed": bool(manifest.manifest_signed),
        "coordinator_pubkey": str(manifest.coordinator_pubkey),
        "manifest_signature": str(manifest.manifest_signature),
        "coordinator_id": manifest.coordinator_id,
        "leader_id": manifest.leader_id,
        "validator_epoch": int(manifest.validator_epoch),
        "validator_set_hash": manifest.validator_set_hash,
        "validator_count": len(manifest.validators),
        "helper_count": len(helper_ids),
        "helper_capacity_bound": any(int(getattr(binding, "helper_capacity_units", 0) or 0) > 0 for binding in manifest.helper_bindings),
        "capability_restricted_lane_count": sum(1 for binding in manifest.helper_bindings if bool(getattr(binding, "capability_restricted", False))),
        "helper_lane_cost_units": int(total_lane_cost_units),
        "helper_ids": list(helper_ids),
        "serial_lane_ids": list(manifest.serial_lane_ids),
        "local_role": manifest.role_for_node(local_node_id),
        "helper_bindings": [binding.to_json() for binding in manifest.helper_bindings],
    }


__all__ = [
    "LaneHelperBinding",
    "ValidatorExecutionManifest",
    "build_validator_execution_manifest",
    "sign_validator_execution_manifest",
    "validator_execution_summary",
    "verify_validator_execution_manifest",
]
