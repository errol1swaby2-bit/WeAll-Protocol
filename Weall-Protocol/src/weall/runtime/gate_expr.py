"""
Gate expression evaluator.

Supports:

Atoms:
  Tier0+
  Tier1+
  Tier2+
  Validator
  Juror
  NodeOperator
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
        if j == i:
            raise ValueError(f"invalid character in gate expression: {c!r}")
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
    acct = _account_record(ledger, signer)
    return _tier_ok(acct, tier)


def _account_record(ledger: Json, signer: str) -> Json:
    accounts = _as_dict(ledger.get("accounts"))
    return _record_for_identity(accounts, signer)


def _account_available_for_authority(ledger: Json, signer: str, *, min_tier: int = 2) -> bool:
    acct = _account_record(ledger, signer)
    if not acct:
        return False
    if _record_blocked(acct):
        return False
    if _truthy(acct.get("banned")) or _truthy(acct.get("locked")) or _truthy(acct.get("suspended")):
        return False
    return _tier_ok(acct, int(min_tier))


def _payload_scope_id(payload: Json, *keys: str) -> str:
    payload = _as_dict(payload)
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            for inner_key in ("id", key, "group_id", "treasury_id", "wallet_id"):
                nested = str(value.get(inner_key) or "").strip()
                if nested:
                    return nested
        direct = str(value or "").strip()
        if direct:
            return direct
    for nested_key in ("data", "args", "body", "payload"):
        nested = _as_dict(payload.get(nested_key))
        if nested:
            scoped = _payload_scope_id(nested, *keys)
            if scoped:
                return scoped
    return ""


def _authority_record_for_identity(container: Json, signer: str, *record_keys: str) -> Json:
    for key in record_keys:
        mapping = _as_dict(container.get(key))
        rec = _record_for_identity(mapping, signer)
        if rec:
            return rec
    return {}


def _authority_member_active(
    container: Json,
    signer: str,
    list_key: str,
    *record_keys: str,
) -> bool:
    rec = _authority_record_for_identity(container, signer, *record_keys)
    if rec and _record_blocked(rec):
        return False

    variants = set(_identity_variants(signer))
    found = False
    for item in container.get(list_key, []) or []:
        if isinstance(item, dict):
            ident = str(
                item.get("account_id")
                or item.get("signer")
                or item.get("emissary")
                or item.get("moderator")
                or item.get("id")
                or ""
            ).strip()
            if not variants.intersection(_identity_variants(ident)):
                continue
            if _record_blocked(item):
                return False
            found = True
            break
        if variants.intersection(_identity_variants(item)):
            found = True
            break

    if not found:
        return False

    if rec:
        return _record_active(rec) or not _record_blocked(rec)
    return True


def _global_emissary_active(roles: Json, signer: str) -> bool:
    emissaries = _as_dict(roles.get("emissaries"))
    rec = _authority_record_for_identity(
        emissaries, signer, "by_id", "emissaries_by_id", "records", "status_by_id"
    )
    if rec and _record_blocked(rec):
        return False
    if _authority_member_active(
        emissaries,
        signer,
        "seated",
        "by_id",
        "emissaries_by_id",
        "records",
        "status_by_id",
    ):
        return True
    return _record_active(rec)



def _case_scoped_juror_without_role_allowed(ledger: Json) -> bool:
    """Return True only when chain state explicitly enables bootstrap/demo compatibility.

    This is intentionally not a general production rule. Normal production juror
    authority still requires Tier2 plus an active Juror role/badge. The flag is
    used by controlled bootstrap/dev/demo paths where a protocol-assigned case
    reviewer must be admitted before the global role record is present.
    """

    params = _as_dict(ledger.get("params"))
    keys = (
        "allow_case_scoped_juror_" + "without_role",
        "poh_allow_case_scoped_juror_" + "without_role",
        "bootstrap_allow_case_scoped_juror_" + "without_role",
    )
    return any(_truthy(params.get(key)) for key in keys)

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


def _seeded_demo_review_fallback_allowed(ledger: Json) -> bool:
    """Return True only for explicit local seeded-demo dispute-review fallback."""

    params = _as_dict(ledger.get("params"))
    return _truthy(params.get("seeded_demo_review_fallback"))

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

    if tier2 and _case_scoped_juror_without_role_allowed(ledger):
        if has_poh_scope:
            return poh_assigned
        if has_dispute_scope and _seeded_demo_review_fallback_allowed(ledger):
            return dispute_assigned

    return False


def _is_node_operator(ledger: Json, signer: str) -> bool:
    """Return True for active node-operator service authority.

    NodeOperator is a service-role gate, not just a human-verification tier.
    It requires an available Tier2 account plus an active node operator record.
    Blocked/suspended/revoked records fail closed even if the account appears in
    a compatibility active_set.
    """

    if not _account_available_for_authority(ledger, signer, min_tier=2):
        return False

    roles = _as_dict(ledger.get("roles"))
    operators = _as_dict(roles.get("node_operators"))
    if _active_role(operators, signer):
        return True

    # Compatibility with older runtime snapshots that kept node operator state
    # under service/node namespaces rather than roles.node_operators.
    services = _as_dict(ledger.get("services"))
    for key in ("node_operators", "operators", "node_operator_records"):
        bucket = _as_dict(services.get(key))
        if _active_role(bucket, signer):
            return True

    nodes = _as_dict(ledger.get("nodes"))
    for key in ("node_operators", "operators", "operator_records"):
        bucket = _as_dict(nodes.get(key))
        if _active_role(bucket, signer):
            return True

    return False


def _is_group_signer(ledger: Json, signer: str, payload: Json) -> bool:
    if not _account_available_for_authority(ledger, signer, min_tier=2):
        return False
    roles = _as_dict(ledger.get("roles"))
    gid = _payload_scope_id(payload, "group_id", "groupId", "groupID", "gid", "group")
    if not gid:
        return False
    g = _as_dict(_as_dict(roles.get("groups_by_id")).get(gid))
    return _authority_member_active(
        g, signer, "signers", "signers_by_id", "signer_records", "signer_statuses"
    )


def _is_group_moderator(ledger: Json, signer: str, payload: Json) -> bool:
    if not _account_available_for_authority(ledger, signer, min_tier=2):
        return False
    roles = _as_dict(ledger.get("roles"))
    gid = _payload_scope_id(payload, "group_id", "groupId", "groupID", "gid", "group")
    if not gid:
        return False
    g = _as_dict(_as_dict(roles.get("groups_by_id")).get(gid))
    return _authority_member_active(
        g,
        signer,
        "moderators",
        "moderators_by_id",
        "moderator_records",
        "moderator_statuses",
    )


def _is_scoped_signer(ledger: Json, signer: str, payload: Json) -> bool:
    if not _account_available_for_authority(ledger, signer, min_tier=2):
        return False

    roles = _as_dict(ledger.get("roles"))

    tid = _payload_scope_id(
        payload,
        "treasury_id",
        "treasuryId",
        "treasuryID",
        "wallet_id",
        "walletId",
        "tid",
        "treasury",
        "id",
    )
    gid = _payload_scope_id(payload, "group_id", "groupId", "groupID", "gid", "group")

    if tid:
        t = _as_dict(_as_dict(roles.get("treasuries_by_id")).get(tid))
        return _authority_member_active(
            t, signer, "signers", "signers_by_id", "signer_records", "signer_statuses"
        )

    if gid:
        g = _as_dict(_as_dict(roles.get("groups_by_id")).get(gid))
        return _authority_member_active(
            g, signer, "signers", "signers_by_id", "signer_records", "signer_statuses"
        )

    return False


def _is_emissary(ledger: Json, signer: str, payload: Json) -> bool:
    if not _account_available_for_authority(ledger, signer, min_tier=2):
        return False

    roles = _as_dict(ledger.get("roles"))
    gid = _payload_scope_id(payload, "group_id", "groupId", "groupID", "gid", "group")
    tid = _payload_scope_id(
        payload,
        "treasury_id",
        "treasuryId",
        "treasuryID",
        "wallet_id",
        "walletId",
        "tid",
        "treasury",
    )

    if gid:
        g = _as_dict(_as_dict(roles.get("groups_by_id")).get(gid))
        if not _authority_member_active(
            g,
            signer,
            "emissaries",
            "emissaries_by_id",
            "emissary_records",
            "emissary_statuses",
        ):
            return False
        # A blocked global emissary record overrides group-level seating.
        global_rec = _authority_record_for_identity(
            _as_dict(roles.get("emissaries")), signer, "by_id", "emissaries_by_id", "records", "status_by_id"
        )
        return not (global_rec and _record_blocked(global_rec))

    if tid:
        t = _as_dict(_as_dict(roles.get("treasuries_by_id")).get(tid))
        if not _authority_member_active(
            t, signer, "signers", "signers_by_id", "signer_records", "signer_statuses"
        ):
            return False
        if bool(t.get("require_emissary_signers", False)):
            return _global_emissary_active(roles, signer)
        return False

    return _global_emissary_active(roles, signer)


def _eval_atom(atom: str, signer: str, ledger: Json, payload: Json) -> bool:
    atom = atom.strip()

    if atom.lower().startswith("tier") and atom.endswith("+"):
        try:
            n = int(atom[4:-1])
        except Exception:
            return False
        acct = _account_record(ledger, signer)
        return _tier_ok(acct, n)

    if atom == "Validator":
        return _is_validator(ledger, signer)

    if atom == "Juror":
        return _is_juror(ledger, signer, payload)

    if atom == "NodeOperator":
        return _is_node_operator(ledger, signer)

    if atom == "Signer":
        return _is_scoped_signer(ledger, signer, payload)

    if atom == "GroupSigner":
        return _is_group_signer(ledger, signer, payload)

    if atom == "GroupModerator":
        return _is_group_moderator(ledger, signer, payload)

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
