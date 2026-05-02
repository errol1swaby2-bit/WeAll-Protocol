"""
Gate expression evaluator.

Supports:

Atoms:
  Tier0+
  Tier1+
  Tier2+
  Validator
  Juror
  Signer
  Emissary

Operators:
  &  (AND)
  |  (OR)

Precedence:
  AND binds tighter than OR.

This module must be deterministic and fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

Json = dict[str, Any]


# ============================================================
# Tokenizer
# ============================================================


@dataclass(frozen=True)
class _Tok:
    kind: str
    text: str


def _tokenize(expr: str) -> list[_Tok]:
    s = (expr or "").strip()
    out: list[_Tok] = []
    i = 0
    n = len(s)

    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "&|()":
            out.append(_Tok(c, c))
            i += 1
            continue
        j = i
        while j < n and (s[j].isalnum() or s[j] in "_+-"):
            j += 1
        out.append(_Tok("ID", s[i:j]))
        i = j

    out.append(_Tok("EOF", ""))
    return out


# ============================================================
# Parser
# ============================================================


class _ParseError(Exception):
    pass


@dataclass
class _Node:
    kind: str  # ATOM | AND | OR
    value: str = ""
    left: _Node | None = None
    right: _Node | None = None


class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0

    def _cur(self) -> _Tok:
        return self.toks[self.i]

    def _eat(self, kind: str) -> None:
        if self._cur().kind != kind:
            raise _ParseError(f"expected {kind}, got {self._cur().kind}")
        self.i += 1

    def parse(self) -> _Node:
        node = self._parse_or()
        if self._cur().kind != "EOF":
            raise _ParseError("unexpected token")
        return node

    def _parse_or(self) -> _Node:
        node = self._parse_and()
        while self._cur().kind == "|":
            self._eat("|")
            rhs = self._parse_and()
            node = _Node("OR", left=node, right=rhs)
        return node

    def _parse_and(self) -> _Node:
        node = self._parse_term()
        while self._cur().kind == "&":
            self._eat("&")
            rhs = self._parse_term()
            node = _Node("AND", left=node, right=rhs)
        return node

    def _parse_term(self) -> _Node:
        t = self._cur()
        if t.kind == "ID":
            self._eat("ID")
            return _Node("ATOM", value=t.text)
        if t.kind == "(":
            self._eat("(")
            node = self._parse_or()
            self._eat(")")
            return node
        raise _ParseError("unexpected token")


# ============================================================
# Helpers
# ============================================================


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _ledger_from_any(obj: Any) -> Json:
    """
    Accept:
      - dict ledger
      - LedgerView
    """
    if isinstance(obj, dict):
        return obj

    # LedgerView compatibility
    if hasattr(obj, "to_ledger"):
        try:
            return obj.to_ledger()
        except Exception:
            return {}

    if hasattr(obj, "ledger"):
        led = obj.ledger
        if isinstance(led, dict):
            return led

    return {}


# ============================================================
# Atom evaluation
# ============================================================


def _tier_ok(acct: Json, n: int) -> bool:
    if n < 0 or n > 2:
        return False
    try:
        tier = int(acct.get("poh_tier") or 0)
    except Exception:
        tier = 0
    tier = max(0, min(2, tier))
    return tier >= n


def _identity_variants(value: Any) -> list[str]:
    s = str(value or "").strip()
    if not s:
        return []
    base = s[1:] if s.startswith("@") else s
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (s, base, f"@{base}" if base else ""):
        c = str(candidate or "").strip()
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _matches_identity_collection(signer: str, values: Any) -> bool:
    variants = set(_identity_variants(signer))
    for value in values or []:
        if variants.intersection(_identity_variants(value)):
            return True
    return False


_BLOCKED_AUTHORITY_STATUSES = {
    "banned",
    "blocked",
    "declined",
    "disabled",
    "inactive",
    "removed",
    "replaced",
    "retired",
    "revoked",
    "suspended",
}

_ACTIVE_AUTHORITY_STATUSES = {
    "active",
    "activated",
    "enabled",
    "juror",
    "live",
    "validator",
}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "active", "enabled"}
    return False


def _record_blocked(rec: Any) -> bool:
    if not isinstance(rec, dict):
        return False
    for key in ("banned", "blocked", "disabled", "removed", "replaced", "revoked", "suspended"):
        if _truthy(rec.get(key)):
            return True
    status = str(rec.get("status") or "").strip().lower()
    return status in _BLOCKED_AUTHORITY_STATUSES


def _record_active(rec: Any) -> bool:
    if not isinstance(rec, dict):
        return False
    if _record_blocked(rec):
        return False
    if _truthy(rec.get("active")) or _truthy(rec.get("activated")) or _truthy(rec.get("enabled")):
        return True
    status = str(rec.get("status") or "").strip().lower()
    return status in _ACTIVE_AUTHORITY_STATUSES


def _record_for_identity(mapping: Json, signer: str) -> Json:
    variants = _identity_variants(signer)
    for variant in variants:
        rec = mapping.get(variant)
        if isinstance(rec, dict):
            return rec
    return {}


def _collection_has_blocked_record(mapping: Json, signer: str) -> bool:
    rec = _record_for_identity(mapping, signer)
    return bool(rec) and _record_blocked(rec)


def _active_role(bucket: Json, signer: str) -> bool:
    by_id = _as_dict(bucket.get("by_id"))
    if _collection_has_blocked_record(by_id, signer):
        return False
    if _matches_identity_collection(signer, bucket.get("active_set", [])):
        return True
    return _record_active(_record_for_identity(by_id, signer))


def _account_has_tier(ledger: Json, signer: str, tier: int) -> bool:
    acct = _as_dict(_as_dict(ledger.get("accounts")).get(signer))
    return _tier_ok(acct, tier)


def _case_scoped_juror_without_role_allowed(ledger: Json) -> bool:
    params = _as_dict(ledger.get("params"))
    for key in (
        "allow_case_scoped_juror_without_role",
        "poh_allow_case_scoped_juror_without_role",
        "bootstrap_allow_case_scoped_juror_without_role",
    ):
        if key in params:
            return _truthy(params.get(key))
    return False


def _active_by_id(mapping: Json, signer: str) -> bool:
    return _record_active(_record_for_identity(mapping, signer))


def _is_validator(ledger: Json, signer: str) -> bool:
    """Return True only for active validator authority.

    Registry membership alone is deliberately insufficient. Public production
    validator authority must come from an active validator set or an active
    validator record. This keeps stale candidates, inactive registry entries,
    and compatibility metadata from satisfying Validator-gated protocol actions.
    """

    roles = _as_dict(ledger.get("roles"))
    rv = _as_dict(roles.get("validators"))
    if _active_role(rv, signer):
        return True

    consensus = _as_dict(ledger.get("consensus"))
    validator_set = _as_dict(consensus.get("validator_set"))
    registry = _as_dict(_as_dict(consensus.get("validators")).get("registry"))
    if _collection_has_blocked_record(registry, signer):
        return False
    if _matches_identity_collection(signer, validator_set.get("active_set", [])):
        return True
    if _active_by_id(registry, signer):
        return True

    validators = _as_dict(ledger.get("validators"))
    legacy_registry = _as_dict(validators.get("registry"))
    if _collection_has_blocked_record(legacy_registry, signer):
        return False
    if _active_by_id(legacy_registry, signer):
        return True

    return False


def _payload_dispute_id(payload: Json) -> str:
    payload = _as_dict(payload)
    direct = str(payload.get("dispute_id") or "").strip()
    if direct:
        return direct
    for key in ("data", "args", "body", "payload"):
        nested = _as_dict(payload.get(key))
        dispute_id = str(nested.get("dispute_id") or "").strip()
        if dispute_id:
            return dispute_id
    return ""


def _dispute_assignment_match(ledger: Json, signer: str, payload: Json) -> bool:
    dispute_id = _payload_dispute_id(payload)
    if not dispute_id:
        return False
    disputes = _as_dict(ledger.get("disputes_by_id"))
    dispute = _as_dict(disputes.get(dispute_id))
    if not dispute:
        return False

    jurors = _as_dict(dispute.get("jurors"))
    signer_variants = set(_identity_variants(signer))
    for juror_id, rec in jurors.items():
        if not signer_variants.intersection(_identity_variants(juror_id)):
            continue
        if isinstance(rec, dict):
            status = str(rec.get("status") or "").strip().lower()
            if status in {"assigned", "accepted", "present", "attendance_marked", "voted"}:
                return True
        return True

    if _matches_identity_collection(signer, dispute.get("assigned_jurors", [])):
        return True

    if _matches_identity_collection(signer, dispute.get("eligible_juror_ids", [])):
        return True

    return False


def _payload_case_id(payload: Json) -> str:
    payload = _as_dict(payload)
    direct = str(payload.get("case_id") or "").strip()
    if direct:
        return direct
    for key in ("data", "args", "body", "payload"):
        nested = _as_dict(payload.get(key))
        case_id = str(nested.get("case_id") or "").strip()
        if case_id:
            return case_id
    return ""


def _poh_juror_assignment_match(ledger: Json, signer: str, payload: Json) -> bool:
    """Return True when ``signer`` is assigned on a canonical PoH case.

    Async and live PoH reviewer actions are Juror-gated at admission so
    under-qualified accounts cannot submit review transactions directly. A
    protocol-assigned PoH reviewer, however, may not also be enrolled in the
    global juror role during controlled bootstrap/devnet flows. The canonical
    case assignment is enough to admit the transaction; execution still
    re-checks assignment, tier, attendance, role, double-vote, and finalization
    rules fail-closed.
    """

    case_id = _payload_case_id(payload)
    if not case_id:
        return False

    poh = _as_dict(ledger.get("poh"))
    signer_variants = set(_identity_variants(signer))

    for cases_key in ("async_cases", "live_cases", "tier2_cases"):
        case = _as_dict(_as_dict(poh.get(cases_key)).get(case_id))
        if not case:
            continue
        jurors = case.get("jurors")

        if isinstance(jurors, dict):
            for juror_id, rec in jurors.items():
                if not signer_variants.intersection(_identity_variants(juror_id)):
                    continue
                if isinstance(rec, dict):
                    if bool(rec.get("replaced", False)):
                        return False
                    status = str(rec.get("status") or "").strip().lower()
                    if status in {"declined", "replaced", "removed"}:
                        return False
                return True

        if isinstance(jurors, list):
            for item in jurors:
                if isinstance(item, dict):
                    juror_id = str(
                        item.get("juror_id")
                        or item.get("account_id")
                        or item.get("juror")
                        or ""
                    ).strip()
                    status = str(item.get("status") or "").strip().lower()
                    if status in {"declined", "replaced", "removed"}:
                        continue
                else:
                    juror_id = str(item or "").strip()
                if juror_id and signer_variants.intersection(_identity_variants(juror_id)):
                    return True

        assigned = case.get("assigned_jurors") or case.get("eligible_juror_ids")
        if _matches_identity_collection(signer, assigned):
            return True

    return False

def _is_juror(ledger: Json, signer: str, payload: Json) -> bool:
    """Return True for active Juror authority.

    Juror is a service authority, not merely a PoH tier or case label. In normal
    production posture it requires Tier2 plus an active Juror role/badge.
    Case-scoped assignment is still required for case-bound payloads, but it is
    not sufficient by itself unless an explicit chain-state bootstrap flag is
    present. Validators no longer inherit Juror authority implicitly.
    """

    has_dispute_scope = bool(_payload_dispute_id(payload))
    has_poh_scope = bool(_payload_case_id(payload))
    dispute_assigned = _dispute_assignment_match(ledger, signer, payload) if has_dispute_scope else False
    poh_assigned = _poh_juror_assignment_match(ledger, signer, payload) if has_poh_scope else False

    tier2 = _account_has_tier(ledger, signer, 2)
    roles = _as_dict(ledger.get("roles"))
    jurors = _as_dict(roles.get("jurors"))
    active_juror = _active_role(jurors, signer)

    if active_juror:
        if not tier2:
            return False
        if has_dispute_scope:
            return dispute_assigned
        if has_poh_scope:
            return poh_assigned
        return True

    # Transitional bootstrap/devnet posture: case-scoped juror authority without
    # a global Juror role is allowed only when the chain-state params explicitly
    # opt in. This keeps production fail-closed while preserving deterministic
    # bootstrap testability.
    if tier2 and _case_scoped_juror_without_role_allowed(ledger):
        return dispute_assigned or poh_assigned

    return False


def _is_scoped_signer(ledger: Json, signer: str, payload: Json) -> bool:
    roles = _as_dict(ledger.get("roles"))

    tid = str(payload.get("treasury_id") or "")
    gid = str(payload.get("group_id") or "")

    if tid:
        t = _as_dict(_as_dict(roles.get("treasuries_by_id")).get(tid))
        return signer in {str(x) for x in t.get("signers", [])}

    if gid:
        g = _as_dict(_as_dict(roles.get("groups_by_id")).get(gid))
        return signer in {str(x) for x in g.get("signers", [])}

    return False


def _is_emissary(ledger: Json, signer: str, payload: Json) -> bool:
    roles = _as_dict(ledger.get("roles"))
    gid = str(payload.get("group_id") or "")

    if gid:
        g = _as_dict(_as_dict(roles.get("groups_by_id")).get(gid))
        return signer in {str(x) for x in g.get("emissaries", [])}

    return False


def _eval_atom(atom: str, signer: str, ledger: Json, payload: Json) -> bool:
    atom = atom.strip()

    if atom.lower().startswith("tier") and atom.endswith("+"):
        try:
            n = int(atom[4:-1])
        except Exception:
            return False
        acct = _as_dict(_as_dict(ledger.get("accounts")).get(signer))
        return _tier_ok(acct, n)

    if atom == "Validator":
        return _is_validator(ledger, signer)

    if atom == "Juror":
        return _is_juror(ledger, signer, payload)

    if atom == "Signer":
        return _is_scoped_signer(ledger, signer, payload)

    if atom == "Emissary":
        return _is_emissary(ledger, signer, payload)

    return False


# ============================================================
# Public API
# ============================================================


def eval_gate(
    expr: str,
    *,
    signer: str,
    state: Any = None,
    ledger: Any = None,
    payload: Json | None = None,
    tx_type: str = "",
) -> tuple[bool, Json]:
    """
    Accepts both `state=` and `ledger=` for backward compatibility.
    """

    source = state if state is not None else ledger
    ledger_dict = _ledger_from_any(source)

    expr0 = (expr or "").strip()
    if not expr0:
        return True, {}

    try:
        ast = _Parser(_tokenize(expr0)).parse()
    except Exception as e:
        return False, {"error": f"parse:{e}", "expr": expr0}

    def _eval(node: _Node) -> bool:
        if node.kind == "ATOM":
            return _eval_atom(node.value, signer, ledger_dict, payload or {})
        if node.kind == "AND":
            return _eval(node.left) and _eval(node.right)
        if node.kind == "OR":
            return _eval(node.left) or _eval(node.right)
        return False

    ok = _eval(ast)
    return ok, {"expr": expr0}
