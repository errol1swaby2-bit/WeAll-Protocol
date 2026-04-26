"""
Gate expression evaluator.

Supports:

Atoms:
  TierN+              (e.g. Tier3+)
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
    try:
        tier = int(acct.get("poh_tier") or 0)
    except Exception:
        tier = 0
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


def _active_by_id(mapping: Json, signer: str) -> bool:
    variants = _identity_variants(signer)
    for variant in variants:
        rec = mapping.get(variant)
        if not isinstance(rec, dict):
            continue
        if bool(rec.get("active", False)):
            return True
        status = str(rec.get("status") or "").strip().lower()
        if status in {"active", "activated", "validator", "juror"}:
            return True
    return False


def _is_validator(ledger: Json, signer: str) -> bool:
    roles = _as_dict(ledger.get("roles"))
    validators = _as_dict(ledger.get("validators"))

    if _matches_identity_collection(signer, _as_dict(validators.get("registry")).keys()):
        return True

    rv = _as_dict(roles.get("validators"))
    if _matches_identity_collection(signer, rv.get("active_set", [])):
        return True
    if _active_by_id(_as_dict(rv.get("by_id")), signer):
        return True

    consensus = _as_dict(ledger.get("consensus"))
    validator_set = _as_dict(consensus.get("validator_set"))
    if _matches_identity_collection(signer, validator_set.get("active_set", [])):
        return True
    registry = _as_dict(_as_dict(consensus.get("validators")).get("registry"))
    if _active_by_id(registry, signer) or _matches_identity_collection(signer, registry.keys()):
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

    Tier-2 and Tier-3 PoH reviewer actions are Juror-gated at admission so
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

    for cases_key in ("tier2_cases", "tier3_cases"):
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
    roles = _as_dict(ledger.get("roles"))
    jurors = _as_dict(roles.get("jurors"))

    if _matches_identity_collection(signer, jurors.get("active_set", [])):
        return True
    if _active_by_id(_as_dict(jurors.get("by_id")), signer):
        return True

    # Live dispute posture: when a dispute has already deterministically assigned
    # this signer as a juror/reviewer, juror-gated actions on that dispute must
    # admit against the canonical dispute assignment state even if the separate
    # global juror registry is not populated yet during bootstrap.
    if _dispute_assignment_match(ledger, signer, payload):
        return True

    # Protocol-native PoH posture: reviewer authority is case-scoped. A Tier-2
    # or Tier-3 account that was assigned on the canonical PoH case may submit
    # the corresponding juror-gated reviewer transactions without requiring a
    # separate global role enrollment.
    if _poh_juror_assignment_match(ledger, signer, payload):
        return True

    # Bootstrap posture: a live active validator may need to perform
    # juror-gated review actions while the network is still operated by a
    # one-account validator set. Keep this deterministic and identity-normalized.
    return _is_validator(ledger, signer)


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
