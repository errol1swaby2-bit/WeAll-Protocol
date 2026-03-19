"""
Gate expression evaluator.

Supports:

Atoms:
  TierN+              (e.g. Tier3+)
  Validator
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


def _is_validator(ledger: Json, signer: str) -> bool:
    roles = _as_dict(ledger.get("roles"))
    validators = _as_dict(ledger.get("validators"))

    if signer in _as_dict(validators.get("registry")):
        return True

    rv = _as_dict(roles.get("validators"))
    if signer in {str(x) for x in rv.get("active_set", [])}:
        return True

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
