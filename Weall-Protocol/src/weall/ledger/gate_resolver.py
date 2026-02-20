# src/weall/ledger/gate_resolver.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from weall.ledger.state import LedgerView


@dataclass(frozen=True, slots=True)
class AuthzVerdict:
    ok: bool
    reason: str
    details: Dict[str, Any]

    @staticmethod
    def allow(reason: str = "ok", details: Optional[Dict[str, Any]] = None) -> "AuthzVerdict":
        return AuthzVerdict(True, reason, details or {})

    @staticmethod
    def deny(reason: str, details: Optional[Dict[str, Any]] = None) -> "AuthzVerdict":
        return AuthzVerdict(False, reason, details or {})


def _norm_gate(gate: str) -> str:
    return (gate or "").strip()


def _lower(s: str) -> str:
    return (s or "").strip().lower()


def _parse_tier_gate(g: str) -> Optional[Tuple[int, bool]]:
    """
    Parses tier gates like:
      - "Tier0+"
      - "Tier1+"
      - "Tier2"
      - "tier3+"

    Returns (min_tier, plus) where plus means >= min_tier.
    If plus is False, treat as >= min_tier anyway (we don't support exact-tier-only gating yet).
    """
    s = _lower(g).replace(" ", "")
    if not s.startswith("tier"):
        return None
    rest = s[4:]
    plus = rest.endswith("+")
    if plus:
        rest = rest[:-1]

    if rest == "":
        return None

    try:
        t = int(rest)
    except Exception:
        return None

    if t < 0:
        t = 0
    return (t, plus)


def _parse_role_gate(g: str) -> Optional[str]:
    """
    Parses role gates like:
      - "juror"
      - "validator"
      - "node_operator"
      - "emissary"
      - "gov_executor"
    """
    s = _lower(g).replace(" ", "").replace("-", "_")
    if s in ("juror", "jurors"):
        return "juror_active"
    if s in ("validator", "validators"):
        return "validator"
    if s in ("node_operator", "nodeoperator", "operator"):
        return "node_operator_active"
    if s in ("emissary", "emissaries"):
        return "emissary_active"
    if s in ("gov_executor", "govexecutor", "executor"):
        return "gov_executor"
    return None


def _split_top_level(expr: str, sep: str) -> list[str]:
    """
    Deterministic, minimal splitter for OR/AND.
    No parentheses support yet (by design for simplicity).
    """
    parts = [p.strip() for p in expr.split(sep)]
    return [p for p in parts if p]


def _extract_ids(payload: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    """
    Best-effort deterministic extraction of (group_id, treasury_id) from payload.

    Supported keys (first match wins):
      group_id:    group_id, groupId, group, groupID, gid
      treasury_id: treasury_id, treasuryId, treasury, treasuryID, tid

    If group/treasury values are dicts, checks inner keys: id, group_id, treasury_id.
    """
    if not isinstance(payload, dict) or not payload:
        return None, None

    def _s(x: Any) -> Optional[str]:
        if isinstance(x, str) and x.strip():
            return x.strip()
        if isinstance(x, int):
            return str(x)
        return None

    def _from_obj(obj: Any) -> Optional[str]:
        if isinstance(obj, dict):
            for k in ("id", "group_id", "treasury_id", "groupId", "treasuryId"):
                v = obj.get(k)
                sv = _s(v)
                if sv:
                    return sv
        return _s(obj)

    group_id: Optional[str] = None
    treasury_id: Optional[str] = None

    for k in ("group_id", "groupId", "groupID", "gid", "group"):
        if k in payload:
            group_id = _from_obj(payload.get(k))
            if group_id:
                break

    for k in ("treasury_id", "treasuryId", "treasuryID", "tid", "treasury"):
        if k in payload:
            treasury_id = _from_obj(payload.get(k))
            if treasury_id:
                break

    return group_id, treasury_id


def _eval_atom(
    ledger: LedgerView,
    account_id: str,
    atom: str,
    *,
    tx_type: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> AuthzVerdict:
    """
    Evaluate a single gate atom (no AND/OR).
    """
    gate = _norm_gate(atom)
    if not gate:
        return AuthzVerdict.deny("empty_gate", {})

    # Universal denies (deterministic)
    if ledger.is_banned(account_id):
        return AuthzVerdict.deny("banned", {"account": account_id})
    if ledger.is_locked(account_id):
        return AuthzVerdict.deny("locked", {"account": account_id})

    # Tier gate
    tier_parsed = _parse_tier_gate(gate)
    if tier_parsed is not None:
        min_tier, _plus = tier_parsed
        have = ledger.get_poh_tier(account_id)
        if have >= min_tier:
            return AuthzVerdict.allow("tier_ok", {"have": have, "need": min_tier})
        return AuthzVerdict.deny("tier_too_low", {"have": have, "need": min_tier})

    # Scoped signer/moderator gates (require payload scope)
    gate_l = _lower(gate).replace(" ", "").replace("-", "")

    group_id, treasury_id = _extract_ids(payload)

    if gate_l == "signer":
        # "Signer" is intentionally scope-based: it must be derivable from tx payload.
        # If both scopes exist, treasury takes precedence (more specific in practice),
        # otherwise fall back to group scope.
        if treasury_id:
            ok = ledger.is_treasury_signer(account_id, treasury_id)
            if ok:
                return AuthzVerdict.allow("treasury_signer_ok", {"treasury_id": treasury_id})
            return AuthzVerdict.deny(
                "treasury_signer_required",
                {"treasury_id": treasury_id, "tx_type": tx_type or ""},
            )

        if group_id:
            ok = ledger.is_group_signer(account_id, group_id)
            if ok:
                return AuthzVerdict.allow("group_signer_ok", {"group_id": group_id})
            return AuthzVerdict.deny(
                "group_signer_required",
                {"group_id": group_id, "tx_type": tx_type or ""},
            )

        return AuthzVerdict.deny(
            "missing_signer_scope",
            {"tx_type": tx_type or "", "need": "treasury_id or group_id in payload"},
        )

    if gate_l == "groupsigner":
        if not group_id:
            return AuthzVerdict.deny(
                "missing_group_scope",
                {"tx_type": tx_type or "", "need": "group_id in payload"},
            )
        ok = ledger.is_group_signer(account_id, group_id)
        if ok:
            return AuthzVerdict.allow("group_signer_ok", {"group_id": group_id})
        return AuthzVerdict.deny("group_signer_required", {"group_id": group_id, "tx_type": tx_type or ""})

    if gate_l == "groupmoderator":
        if not group_id:
            return AuthzVerdict.deny(
                "missing_group_scope",
                {"tx_type": tx_type or "", "need": "group_id in payload"},
            )
        ok = ledger.is_group_moderator(account_id, group_id)
        if ok:
            return AuthzVerdict.allow("group_moderator_ok", {"group_id": group_id})
        return AuthzVerdict.deny("group_moderator_required", {"group_id": group_id, "tx_type": tx_type or ""})

    # Role gate (global)
    role_key = _parse_role_gate(gate)
    if role_key is not None:
        roles = ledger.get_roles(account_id)
        ok = bool(roles.get(role_key, False))
        if ok:
            return AuthzVerdict.allow("role_ok", {"role": role_key})
        return AuthzVerdict.deny("role_required", {"role": role_key})

    # Group membership gate (optional): "group:<name>" or "group=<name>"
    s = _lower(gate)
    if s.startswith("group:") or s.startswith("group="):
        group_name = gate.split(":", 1)[1] if ":" in gate else gate.split("=", 1)[1]
        group_name = (group_name or "").strip()
        if not group_name:
            return AuthzVerdict.deny("bad_group_gate", {"gate": gate})

        roles = ledger.get_roles(account_id)
        groups = roles.get("groups")
        if isinstance(groups, dict) and bool(groups.get(group_name, False)):
            return AuthzVerdict.allow("group_ok", {"group": group_name})
        return AuthzVerdict.deny("group_required", {"group": group_name})

    # Unknown gates fail closed in production
    return AuthzVerdict.deny("unknown_gate", {"gate": gate})


def resolve_signer_authz(
    ledger: LedgerView,
    signer: str,
    gate: str = "",
    *,
    tx_type: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    # Back-compat: newer admission code passes these names.
    gate_expr: Optional[str] = None,
    subject_gate_expr: Optional[str] = None,
) -> AuthzVerdict:
    """Evaluate authorization for a signer.

    Back-compat notes:
      - Older code calls: resolve_signer_authz(ledger, signer, gate="Tier0+")
      - Newer code calls with: gate_expr=..., subject_gate_expr=...

    When gate_expr/subject_gate_expr are provided, we evaluate them as two
    *separate* expressions and require both to pass (fail-fast on the first
    denial). This avoids needing parentheses while staying deterministic.
    """
    if not isinstance(signer, str) or not signer.strip():
        return AuthzVerdict.deny("missing_signer", {})

    # If caller provided the newer names, use them.
    g1 = _norm_gate(gate_expr or gate)
    g2 = _norm_gate(subject_gate_expr or "")

    if g2:
        v1 = resolve_signer_authz(ledger, signer, g1, tx_type=tx_type, payload=payload)
        if not v1.ok:
            return v1
        v2 = resolve_signer_authz(ledger, signer, g2, tx_type=tx_type, payload=payload)
        if not v2.ok:
            return v2
        return AuthzVerdict.allow("gate_ok", {"gate": g1, "subject_gate": g2})

    expr = g1
    if not expr:
        # Default deny: gate must be explicit. Caller typically passes "Tier0+"
        return AuthzVerdict.deny("missing_gate", {})

    or_groups = _split_top_level(expr, "|")
    if not or_groups:
        return AuthzVerdict.deny("bad_gate_expr", {"gate": expr})

    last_denial: Optional[AuthzVerdict] = None

    for group in or_groups:
        and_atoms = _split_top_level(group, "&")
        if not and_atoms:
            continue

        group_ok = True
        group_denial: Optional[AuthzVerdict] = None

        for atom in and_atoms:
            v = _eval_atom(ledger, signer, atom, tx_type=tx_type, payload=payload)
            if not v.ok:
                group_ok = False
                group_denial = v
                break

        if group_ok:
            return AuthzVerdict.allow("gate_ok", {"gate": expr, "matched": group})

        last_denial = group_denial or last_denial

    if last_denial is not None:
        return last_denial
    return AuthzVerdict.deny("gate_denied", {"gate": expr})
