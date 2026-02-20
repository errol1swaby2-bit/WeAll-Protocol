# src/weall/runtime/gates.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from weall.ledger.state import LedgerView

Json = Dict[str, Any]


def _as_str(v: Any) -> str:
    return str(v) if v is not None else ""


def _tier_of(s: str) -> Optional[int]:
    # "Tier3+" -> 3
    s = s.strip()
    if not s.lower().startswith("tier"):
        return None
    s2 = s[4:]
    if s2.endswith("+"):
        s2 = s2[:-1]
    try:
        return int(s2)
    except Exception:
        return None


def _get_active_validators(ledger: LedgerView) -> List[str]:
    roles = ledger.roles if isinstance(ledger.roles, dict) else {}
    validators = roles.get("validators") if isinstance(roles, dict) else None
    if isinstance(validators, dict):
        active = validators.get("active_set")
        if isinstance(active, list):
            return [str(x) for x in active]
    return []


def _is_validator(ledger: LedgerView, signer: str) -> bool:
    return signer in set(_get_active_validators(ledger))


def _get_group(ledger: LedgerView, group_id: str) -> Optional[dict]:
    roles = ledger.roles if isinstance(ledger.roles, dict) else {}
    gbid = roles.get("groups_by_id")
    if isinstance(gbid, dict):
        g = gbid.get(group_id)
        if isinstance(g, dict):
            return g
    return None


def _get_treasury(ledger: LedgerView, treasury_id: str) -> Optional[dict]:
    roles = ledger.roles if isinstance(ledger.roles, dict) else {}
    # tests use roles["treasuries"] in some places, and roles["treasuries_by_id"] elsewhere
    t1 = roles.get("treasuries")
    if isinstance(t1, dict):
        t = t1.get(treasury_id)
        if isinstance(t, dict):
            return t
    t2 = roles.get("treasuries_by_id")
    if isinstance(t2, dict):
        t = t2.get(treasury_id)
        if isinstance(t, dict):
            return t
    return None


def _term_eval(ledger: LedgerView, signer: str, term: str, payload: Optional[dict]) -> Tuple[bool, Optional[Json]]:
    term = term.strip()

    # TierN+
    t = _tier_of(term)
    if t is not None:
        acct = ledger.get_account(signer)
        have = int(acct.get("poh_tier", 0) or 0)
        if have >= t:
            return True, None
        return False, {"reason": "tier_required", "need": t, "have": have}

    if term == "Validator":
        if _is_validator(ledger, signer):
            return True, None
        return False, {"reason": "validator_required"}

    # Scoped signer: treasury_id or group_id
    if term == "Signer":
        p = payload or {}
        tid = _as_str(p.get("treasury_id") or "").strip()
        gid = _as_str(p.get("group_id") or "").strip()

        if not tid and not gid:
            return False, {"reason": "missing_signer_scope"}

        if tid:
            tr = _get_treasury(ledger, tid)
            if not isinstance(tr, dict):
                return False, {"reason": "treasury_signer_required", "treasury_id": tid}
            signers = tr.get("signers")
            if isinstance(signers, list) and signer in [str(x) for x in signers]:
                return True, None
            return False, {"reason": "treasury_signer_required", "treasury_id": tid}

        # group scope
        g = _get_group(ledger, gid)
        if not isinstance(g, dict):
            return False, {"reason": "group_signer_required", "group_id": gid}
        signers = g.get("signers")
        if isinstance(signers, list) and signer in [str(x) for x in signers]:
            return True, None
        return False, {"reason": "group_signer_required", "group_id": gid}

    if term == "GroupSigner":
        p = payload or {}
        gid = _as_str(p.get("group_id") or "").strip()
        if not gid:
            return False, {"reason": "missing_group_scope"}
        g = _get_group(ledger, gid)
        if not isinstance(g, dict):
            return False, {"reason": "group_signer_required", "group_id": gid}
        signers = g.get("signers")
        if isinstance(signers, list) and signer in [str(x) for x in signers]:
            return True, None
        return False, {"reason": "group_signer_required", "group_id": gid}

    if term == "GroupModerator":
        p = payload or {}
        gid = _as_str(p.get("group_id") or "").strip()
        if not gid:
            return False, {"reason": "missing_group_scope"}
        g = _get_group(ledger, gid)
        if not isinstance(g, dict):
            return False, {"reason": "group_moderator_required", "group_id": gid}
        mods = g.get("moderators")
        if isinstance(mods, list) and signer in [str(x) for x in mods]:
            return True, None
        return False, {"reason": "group_moderator_required", "group_id": gid}

    # Unknown term -> deny
    return False, {"reason": "unknown_gate_term", "term": term}


def _tokenize(expr: str) -> List[str]:
    out: List[str] = []
    buf = ""
    for ch in expr:
        if ch in ("&", "|", "(", ")"):
            if buf.strip():
                out.append(buf.strip())
            buf = ""
            out.append(ch)
        else:
            buf += ch
    if buf.strip():
        out.append(buf.strip())
    # drop empty
    return [t for t in out if t.strip()]


def _to_rpn(tokens: List[str]) -> List[str]:
    # Shunting-yard with precedence: & > |
    prec = {"&": 2, "|": 1}
    out: List[str] = []
    ops: List[str] = []
    for t in tokens:
        if t in ("&", "|"):
            while ops and ops[-1] in prec and prec[ops[-1]] >= prec[t]:
                out.append(ops.pop())
            ops.append(t)
        elif t == "(":
            ops.append(t)
        elif t == ")":
            while ops and ops[-1] != "(":
                out.append(ops.pop())
            if ops and ops[-1] == "(":
                ops.pop()
        else:
            out.append(t)
    while ops:
        out.append(ops.pop())
    return out


def resolve_signer_authz(
    *,
    ledger: LedgerView,
    signer: str,
    gate_expr: str,
    payload: Optional[dict] = None,
) -> Tuple[bool, Json]:
    """
    Returns (ok, meta). On deny, meta must include a stable 'reason'
    used by tests (e.g., missing_group_scope, treasury_signer_required, etc).
    """
    expr = gate_expr.strip()
    if not expr:
        return True, {}

    tokens = _tokenize(expr)
    rpn = _to_rpn(tokens)

    stack: List[Tuple[bool, Optional[Json]]] = []
    last_meta: Optional[Json] = None

    for t in rpn:
        if t == "&":
            if len(stack) < 2:
                return False, {"reason": "bad_gate_expr"}
            b2, m2 = stack.pop()
            b1, m1 = stack.pop()
            ok = b1 and b2
            # keep the most specific failing meta if false
            meta = None
            if not ok:
                meta = m1 if not b1 else m2
            stack.append((ok, meta))
            if meta is not None:
                last_meta = meta
        elif t == "|":
            if len(stack) < 2:
                return False, {"reason": "bad_gate_expr"}
            b2, m2 = stack.pop()
            b1, m1 = stack.pop()
            ok = b1 or b2
            meta = None
            if not ok:
                meta = m1 or m2
            stack.append((ok, meta))
            if meta is not None:
                last_meta = meta
        else:
            ok, meta = _term_eval(ledger, signer, t, payload)
            stack.append((ok, meta))
            if meta is not None:
                last_meta = meta

    if len(stack) != 1:
        return False, {"reason": "bad_gate_expr"}

    ok, meta = stack[0]
    if ok:
        return True, {}

    return False, (meta or last_meta or {"reason": "gate_denied"})
