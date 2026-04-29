from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight
from weall.runtime.node_runtime_config import (
    BOOTSTRAP_REGISTRATION,
    MAINTENANCE_RESTRICTED,
    PRODUCTION_SERVICE,
    REFUSED_STARTUP,
    resolve_node_runtime_config_from_env,
)
from weall.runtime.protocol_profile import effective_runtime_consensus_posture

Json = dict[str, Any]

STARTUP_ACTION_ALLOW = "allow"
STARTUP_ACTION_MAINTENANCE_RESTRICTED = "maintenance_restricted"
STARTUP_ACTION_REFUSE_STARTUP = "refuse_startup"


@dataclass(frozen=True, slots=True)
class NodeLifecycleStatus:
    requested_state: str
    effective_state: str
    promotion_preflight_passed: bool
    profile_commitment: str
    schema_version: str
    tx_index_hash: str
    runtime_profile_hash: str
    service_roles_requested: tuple[str, ...]
    service_roles_effective: tuple[str, ...]
    helper_enabled_requested: bool
    helper_enabled_effective: bool
    bft_enabled_requested: bool
    bft_enabled_effective: bool
    signature_verification_required: bool
    signature_verification_effective: bool
    trusted_anchor_required: bool
    trusted_anchor_effective: bool
    promotion_failure_reasons: tuple[str, ...]
    bound_account: str
    account_exists: bool
    node_key_authorized: bool
    poh_tier_required: int
    poh_tier_actual: int
    reputation_required_milli: int
    reputation_actual_milli: int
    banned: bool
    locked: bool
    active_roles: tuple[str, ...]
    suspended_roles: tuple[str, ...]
    startup_action: str
    startup_refusal_required: bool
    peer_profile_enforcement: str
    config_source_summary: Json

    def to_json(self) -> Json:
        return {
            "requested_state": str(self.requested_state),
            "effective_state": str(self.effective_state),
            "promotion_preflight_passed": bool(self.promotion_preflight_passed),
            "profile_commitment": str(self.profile_commitment),
            "schema_version": str(self.schema_version),
            "tx_index_hash": str(self.tx_index_hash),
            "runtime_profile_hash": str(self.runtime_profile_hash),
            "service_roles_requested": list(self.service_roles_requested),
            "service_roles_effective": list(self.service_roles_effective),
            "helper_enabled_requested": bool(self.helper_enabled_requested),
            "helper_enabled_effective": bool(self.helper_enabled_effective),
            "bft_enabled_requested": bool(self.bft_enabled_requested),
            "bft_enabled_effective": bool(self.bft_enabled_effective),
            "signature_verification_required": bool(self.signature_verification_required),
            "signature_verification_effective": bool(self.signature_verification_effective),
            "trusted_anchor_required": bool(self.trusted_anchor_required),
            "trusted_anchor_effective": bool(self.trusted_anchor_effective),
            "promotion_failure_reasons": list(self.promotion_failure_reasons),
            "bound_account": str(self.bound_account),
            "account_exists": bool(self.account_exists),
            "node_key_authorized": bool(self.node_key_authorized),
            "poh_tier_required": int(self.poh_tier_required),
            "poh_tier_actual": int(self.poh_tier_actual),
            "reputation_required_milli": int(self.reputation_required_milli),
            "reputation_actual_milli": int(self.reputation_actual_milli),
            "banned": bool(self.banned),
            "locked": bool(self.locked),
            "active_roles": list(self.active_roles),
            "suspended_roles": list(self.suspended_roles),
            "startup_action": str(self.startup_action),
            "startup_refusal_required": bool(self.startup_refusal_required),
            "peer_profile_enforcement": str(self.peer_profile_enforcement),
            "config_source_summary": dict(self.config_source_summary),
        }


def _profile_commitment_payload(
    *,
    chain_id: str,
    schema_version: str,
    tx_index_hash: str,
    runtime_profile_hash: str,
    requested_state: str,
    effective_state: str,
    roles_requested: tuple[str, ...],
    roles_effective: tuple[str, ...],
    helper_requested: bool,
    helper_effective: bool,
    bft_requested: bool,
    bft_effective: bool,
    trusted_anchor_required: bool,
    sigverify_required: bool,
    peer_profile_enforcement: str,
) -> Json:
    return {
        "chain_id": str(chain_id or ""),
        "schema_version": str(schema_version or ""),
        "tx_index_hash": str(tx_index_hash or ""),
        "runtime_profile_hash": str(runtime_profile_hash or ""),
        "requested_state": str(requested_state),
        "effective_state": str(effective_state),
        "service_roles_requested": list(sorted(roles_requested)),
        "service_roles_effective": list(sorted(roles_effective)),
        "helper_enabled_requested": bool(helper_requested),
        "helper_enabled_effective": bool(helper_effective),
        "bft_enabled_requested": bool(bft_requested),
        "bft_enabled_effective": bool(bft_effective),
        "trusted_anchor_required": bool(trusted_anchor_required),
        "signature_verification_required": bool(sigverify_required),
        "peer_profile_enforcement": str(peer_profile_enforcement or "strict"),
    }


def _profile_commitment(payload: Mapping[str, Any]) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _append_unique(items: list[str], *values: str) -> None:
    seen = set(items)
    for value in values:
        if value and value not in seen:
            items.append(value)
            seen.add(value)


def evaluate_node_lifecycle_status(
    *,
    state: Mapping[str, Any],
    node_id: str,
    chain_id: str,
    schema_version: str,
    tx_index_hash: str,
    runtime_profile_hash: str,
) -> NodeLifecycleStatus:
    posture = effective_runtime_consensus_posture()
    config = resolve_node_runtime_config_from_env()
    requested_state = config.requested_state
    requested_roles = config.requested_roles
    helper_requested = bool(config.helper_enabled_requested)
    bft_requested = bool(config.bft_enabled_requested)
    sigverify_required = bool(posture.get("sigverify_required", False))
    trusted_anchor_required = bool(posture.get("trusted_anchor_required", False))
    sigverify_effective = sigverify_required
    trusted_anchor_effective = trusted_anchor_required

    hard_fail_reasons: list[str] = []
    maintenance_reasons: list[str] = []
    effective_state = requested_state
    effective_roles: tuple[str, ...] = ()

    bound_account = ""
    account_exists = False
    node_key_authorized = False
    poh_tier_required = 0
    poh_tier_actual = 0
    reputation_required_milli = 0
    reputation_actual_milli = 0
    banned = False
    locked = False
    active_roles: tuple[str, ...] = ()
    suspended_roles: tuple[str, ...] = ()
    helper_effective = False
    bft_effective = False

    if config.raw_state and requested_state == REFUSED_STARTUP:
        _append_unique(hard_fail_reasons, "CONFIG_INVALID_PROFILE")
    if config.invalid_roles:
        _append_unique(hard_fail_reasons, "CONFIG_INVALID_SERVICE_ROLE")

    if requested_state == PRODUCTION_SERVICE:
        preflight = evaluate_production_preflight(
            state=state,
            node_id=node_id,
            chain_id=chain_id,
            schema_version=schema_version,
            tx_index_hash=tx_index_hash,
            runtime_profile_hash=runtime_profile_hash,
            requested_roles=requested_roles,
            helper_requested=helper_requested,
            bft_requested=bft_requested,
            sigverify_required=sigverify_effective,
            trusted_anchor_required=trusted_anchor_effective,
        )
        hard_fail_reasons.extend(preflight.hard_fail_reasons)
        maintenance_reasons.extend(preflight.maintenance_reasons)
        bound_account = preflight.bound_account
        account_exists = preflight.account_exists
        node_key_authorized = preflight.node_key_authorized
        poh_tier_required = preflight.poh_tier_required
        poh_tier_actual = preflight.poh_tier_actual
        reputation_required_milli = preflight.reputation_required_milli
        reputation_actual_milli = preflight.reputation_actual_milli
        banned = preflight.banned
        locked = preflight.locked
        active_roles = preflight.active_roles
        suspended_roles = preflight.suspended_roles
        effective_roles = preflight.effective_roles
        helper_effective = preflight.helper_effective
        bft_effective = preflight.bft_effective

        if hard_fail_reasons:
            effective_state = REFUSED_STARTUP
        elif maintenance_reasons:
            effective_state = MAINTENANCE_RESTRICTED
            effective_roles = ()
            helper_effective = False
            bft_effective = False
        else:
            effective_state = PRODUCTION_SERVICE
    elif requested_state == BOOTSTRAP_REGISTRATION:
        effective_state = BOOTSTRAP_REGISTRATION if not hard_fail_reasons else REFUSED_STARTUP
    elif requested_state == MAINTENANCE_RESTRICTED:
        effective_state = MAINTENANCE_RESTRICTED if not hard_fail_reasons else REFUSED_STARTUP
    elif requested_state == REFUSED_STARTUP:
        effective_state = REFUSED_STARTUP
    else:
        _append_unique(hard_fail_reasons, "CONFIG_INVALID_PROFILE")
        effective_state = REFUSED_STARTUP

    all_reasons = tuple(sorted(set([*hard_fail_reasons, *maintenance_reasons])))
    startup_refusal_required = bool(effective_state == REFUSED_STARTUP or hard_fail_reasons)
    startup_action = STARTUP_ACTION_ALLOW
    if startup_refusal_required:
        startup_action = STARTUP_ACTION_REFUSE_STARTUP
    elif effective_state == MAINTENANCE_RESTRICTED:
        startup_action = STARTUP_ACTION_MAINTENANCE_RESTRICTED

    payload = _profile_commitment_payload(
        chain_id=chain_id,
        schema_version=schema_version,
        tx_index_hash=tx_index_hash,
        runtime_profile_hash=runtime_profile_hash,
        requested_state=requested_state,
        effective_state=effective_state,
        roles_requested=requested_roles,
        roles_effective=effective_roles,
        helper_requested=helper_requested,
        helper_effective=helper_effective,
        bft_requested=bft_requested,
        bft_effective=bft_effective,
        trusted_anchor_required=trusted_anchor_effective,
        sigverify_required=sigverify_effective,
        peer_profile_enforcement=config.peer_profile_enforcement,
    )

    return NodeLifecycleStatus(
        requested_state=requested_state,
        effective_state=effective_state,
        promotion_preflight_passed=bool(
            requested_state == PRODUCTION_SERVICE
            and effective_state == PRODUCTION_SERVICE
            and not all_reasons
        ),
        profile_commitment=_profile_commitment(payload),
        schema_version=str(schema_version or ""),
        tx_index_hash=str(tx_index_hash or ""),
        runtime_profile_hash=str(runtime_profile_hash or ""),
        service_roles_requested=requested_roles,
        service_roles_effective=effective_roles,
        helper_enabled_requested=helper_requested,
        helper_enabled_effective=helper_effective,
        bft_enabled_requested=bft_requested,
        bft_enabled_effective=bft_effective,
        signature_verification_required=sigverify_required,
        signature_verification_effective=sigverify_effective,
        trusted_anchor_required=trusted_anchor_required,
        trusted_anchor_effective=trusted_anchor_effective,
        promotion_failure_reasons=all_reasons,
        bound_account=bound_account,
        account_exists=account_exists,
        node_key_authorized=node_key_authorized,
        poh_tier_required=int(poh_tier_required),
        poh_tier_actual=int(poh_tier_actual),
        reputation_required_milli=int(reputation_required_milli),
        reputation_actual_milli=int(reputation_actual_milli),
        banned=bool(banned),
        locked=bool(locked),
        active_roles=active_roles,
        suspended_roles=suspended_roles,
        startup_action=startup_action,
        startup_refusal_required=startup_refusal_required,
        peer_profile_enforcement=str(config.peer_profile_enforcement or "strict"),
        config_source_summary=config.config_source_summary(),
    )
