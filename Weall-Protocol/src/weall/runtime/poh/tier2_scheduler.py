# src/weall/runtime/poh/tier2_scheduler.py
from __future__ import annotations

import os
from typing import Any, Dict, List

from weall.runtime.system_tx_engine import enqueue_system_tx

Json = Dict[str, Any]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return ""


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def _poh_root(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    return poh


def _tier2_cases(state: Json) -> Json:
    poh = _poh_root(state)
    cases = poh.get("tier2_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["tier2_cases"] = cases
    return cases


def _case_needs_assign(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("open", "init", "requested"):
        return False
    jm = case.get("jurors")
    if not isinstance(jm, dict) or len(jm) == 0:
        return True
    return False


def _case_ready_to_finalize(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized"):
        return False

    jm = case.get("jurors")
    if not isinstance(jm, dict) or len(jm) != 3:
        return False

    # Require 3 jurors accepted (True) and verdicts present.
    for _jid, jrec_any in jm.items():
        jrec = _as_dict(jrec_any)
        if jrec.get("accepted") is not True:
            return False
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v not in ("pass", "fail"):
            return False

    return True


def schedule_poh_tier2_system_txs(state: Json, *, next_height: int) -> int:
    """Block-path automation for Tier 2.

    MVP behavior:
      - Assign jurors for open Tier 2 requests (SYSTEM receipt) once per case.
      - Finalize as soon as all 3 verdicts are present (SYSTEM receipt).

    Juror selection is deterministic, seeded by chain tip/height/case_id.

    Environment:
      - WEALL_POH_TIER2_MIN_REP (default 0.0)

    Returns number of queue items enqueued (best-effort, dedupe-safe).
    """
    enq = 0
    min_rep = 0.0
    try:
        min_rep = float(os.environ.get("WEALL_POH_TIER2_MIN_REP", "0.0"))
    except Exception:
        min_rep = 0.0

    cases = _tier2_cases(state)

    for case_id, case_any in list(cases.items()):
        case = _as_dict(case_any)
        cid = _as_str(case.get("case_id") or case_id).strip() or _as_str(case_id).strip()
        if not cid:
            continue

        # ASSIGN
        if _case_needs_assign(case):
            account_id = _as_str(case.get("account_id") or "").strip()
            if account_id:
                try:
                    from weall.runtime.poh.juror_select import pick_tier2_jurors  # type: ignore

                    jurors = pick_tier2_jurors(state=state, case_id=cid, target_account=account_id, n_jurors=3, min_rep=min_rep)
                except Exception:
                    jurors = []

                if isinstance(jurors, list) and len(jurors) == 3:
                    enqueue_system_tx(
                        state,
                        tx_type="POH_TIER2_JUROR_ASSIGN",
                        payload={"case_id": cid, "jurors": jurors},
                        due_height=int(next_height),
                        signer="SYSTEM",
                        once=True,
                        parent=None,
                        phase="post",
                    )
                    enq += 1

        # FINALIZE
        if _case_ready_to_finalize(case):
            enqueue_system_tx(
                state,
                tx_type="POH_TIER2_FINALIZE",
                payload={"case_id": cid, "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enq += 1

    return enq
