from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from weall.runtime.errors import ApplyError

Json = Dict[str, Any]


def _ensure_root(state: Any) -> Json:
    if isinstance(state, dict):
        return state
    if hasattr(state, "to_ledger"):
        try:
            return state.to_ledger()
        except Exception:
            return {}
    return {}


def _is_system_tx(signer: str, root: Json) -> bool:
    system_signer = root.get("params", {}).get("system_signer", "SYSTEM")
    return str(signer) == str(system_signer)


def resolve_signer_authz(
    *,
    signer: str,
    state: Any | None = None,
    ledger: Any | None = None,
    required: Optional[str] = None,
    gate_expr: Optional[str] = None,
    tx_type: str = "",
    payload: Optional[Json] = None,
    root: Optional[Json] = None,
) -> Tuple[bool, Json]:
    """
    Compatibility layer:
      - accept state=
      - accept ledger=
      - accept gate_expr= or required=
    """

    expr = required if required is not None else gate_expr
    if not expr:
        return True, {}

    state0 = state if state is not None else ledger
    root0 = root or _ensure_root(state0 or {})

    if _is_system_tx(signer, root0):
        return True, {}

    try:
        from weall.runtime.gate_expr import eval_gate
    except Exception as e:
        raise ApplyError("invalid_state", "gate_engine_unavailable", {"err": str(e)})

    ok, details = eval_gate(
        expr,
        signer=signer,
        state=root0,
        payload=payload or {},
        tx_type=tx_type or "",
    )

    if ok:
        return True, {}

    return False, details if isinstance(details, dict) else {}
