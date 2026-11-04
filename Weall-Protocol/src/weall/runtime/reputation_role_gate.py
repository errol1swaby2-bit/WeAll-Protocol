from __future__ import annotations

"""Pure, state-rooted reputation role activation predicate.

Policy version 1 retains the historical operative scalar/PoH/manual gates.
Version 2 may be selected only by an explicit chain-committed integer parameter;
missing parameter defaults to version 1. This module does not authorize enabling
v2 on a deployed chain, and does not replace the separate role-specific checks.
"""

from typing import Any

from weall.runtime.poh.state import effective_poh_tier
from weall.runtime.reputation_events import derive_role_eligibility
from weall.runtime.reputation_units import account_reputation_units

Json = dict[str, Any]

ROLE_REVOKE_ALIASES: dict[str, tuple[str, ...]] = {
    "juror": ("juror", "Juror", "ROLE_JUROR", "ROLE_JUROR_ACTIVATE"),
    "node_operator": (
        "node_operator",
        "NodeOperator",
        "Node Operator",
        "ROLE_NODE_OPERATOR",
        "ROLE_NODE_OPERATOR_ACTIVATE",
    ),
    "validator": ("validator", "Validator", "ROLE_VALIDATOR", "ROLE_VALIDATOR_ACTIVATE"),
    "gov_executor": ("gov_executor", "GovExecutor", "ROLE_GOV_EXECUTOR", "ROLE_GOV_EXECUTOR_SET"),
    "emissary": ("emissary", "Emissary", "ROLE_EMISSARY", "ROLE_EMISSARY_SEAT"),
}

# Juror and validator are the only operative roles with direct canonical
# registry mappings. Do not mistake baseline node operator for validator
# authority, or assign unrelated emissary/governance penalties by analogy.
CANONICAL_ACTIVATION_ROLE: dict[str, str] = {
    "juror": "juror_assignment",
    "validator": "validator_operator",
}


def _dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def reputation_role_gate_version(state: Json) -> int:
    params = _dict(state.get("params"))
    version = params.get("reputation_role_gate_version", 1)
    if type(version) is not int or version not in (1, 2):
        return -1
    return version


def role_activation_reputation_decision(
    state: Json,
    account_id: str,
    *,
    role: str,
    minimum_reputation_milli: int = 0,
    include_canonical_diagnostics: bool = False,
) -> Json:
    """Return the exact predicate outcome without mutating the state.

    In v1 canonical event eligibility is diagnostic only. In explicit v2 it
    adds a restriction for mapped operative roles, never grants authority or
    supersedes restrictions from scalar, manual revocation, banned or PoH gates.
    """
    accounts = _dict(state.get("accounts"))
    account = accounts.get(account_id)
    version = reputation_role_gate_version(state)
    required = max(0, int(minimum_reputation_milli))
    mapped = CANONICAL_ACTIVATION_ROLE.get(role, "")
    result: Json = {
        "account_id": account_id,
        "role": role,
        "gate_version": version,
        "version_source": "state.params.reputation_role_gate_version",
        "canonical_role": mapped or None,
        "canonical_enforcement": bool(version == 2 and mapped),
        "required_milli": required,
        "actual_milli": 0,
        "eligible": False,
        "code": "forbidden",
        "reason": "policy_unknown",
        "canonical_eligible": None,
        "canonical_reasons": [],
        "other_role_specific_checks_required": True,
    }
    if not isinstance(account, dict):
        result.update(code="not_found", reason="account_not_found")
        return result
    if bool(account.get("banned", False)) or bool(account.get("locked", False)):
        result["reason"] = "account_restricted"
        return result
    if effective_poh_tier(state, account_id) < 2:
        result["reason"] = "live_verification_required"
        return result
    rep = _dict(state.get("reputation"))
    roles = _dict(_dict(_dict(rep.get("role_eligibility")).get(account_id)).get("roles"))
    aliases = ROLE_REVOKE_ALIASES.get(role, (role,))
    if any(alias in roles and bool(roles[alias]) is False for alias in aliases):
        result["reason"] = "role_eligibility_revoked"
        return result
    actual = account_reputation_units(account, default=0)
    result["actual_milli"] = actual
    if actual < required:
        result["reason"] = "reputation_insufficient"
        return result
    if version not in (1, 2):
        return result

    # No canonical reducer evaluation on v1 consensus apply paths. This keeps
    # historical authorization cost and failure behavior unchanged.
    if mapped and (version == 2 or include_canonical_diagnostics):
        canonical = _dict(derive_role_eligibility(state, account_id).get(mapped))
        result["canonical_eligible"] = canonical.get("eligible") is True
        result["canonical_reasons"] = list(canonical.get("reasons", []))
        if version == 2 and not result["canonical_eligible"]:
            result["reason"] = "canonical_role_reputation_ineligible"
            return result
    result.update(eligible=True, code="ok", reason="eligible")
    return result


def operative_role_reputation_preview(state: Json, account_id: str) -> Json:
    """Public read-model of the operative gate with default chain thresholds.

    Does not include payload-specific thresholds or later responsibility,
    enrollment, signer, validator-readiness, or suspension authorization.
    """
    params = _dict(state.get("params"))
    previews: Json = {}
    for role in ROLE_REVOKE_ALIASES:
        default = 5000 if role == "validator" else 0
        required = default
        for key in (
            "reputation_required_milli",
            f"{role}_reputation_required_milli",
            f"{role}_minimum_reputation_milli",
        ):
            if key in params:
                try:
                    required = max(0, int(params[key]))
                except (TypeError, ValueError):
                    required = default
                break
        previews[role] = role_activation_reputation_decision(
            state,
            account_id,
            role=role,
            minimum_reputation_milli=required,
            include_canonical_diagnostics=True,
        )
    return {
        "gate_version": reputation_role_gate_version(state),
        "scope": "role_activation_reputation_gate_preview_only",
        "payload_specific_requirements_included": False,
        "other_role_specific_checks_required": True,
        "roles": previews,
    }


__all__ = [
    "CANONICAL_ACTIVATION_ROLE",
    "ROLE_REVOKE_ALIASES",
    "operative_role_reputation_preview",
    "reputation_role_gate_version",
    "role_activation_reputation_decision",
]
