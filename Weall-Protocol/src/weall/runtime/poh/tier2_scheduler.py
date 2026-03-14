# src/weall/runtime/poh/tier2_scheduler.py
from __future__ import annotations

import os
from typing import Any, Dict

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


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except Exception:
        return float(default)


def _params_root(state: Json) -> Json:
    params = state.get("params")
    return params if isinstance(params, dict) else {}


def _poh_params(state: Json) -> Json:
    params = _params_root(state)
    poh = params.get("poh")
    return poh if isinstance(poh, dict) else {}


def _param_int(state: Json, key: str, default: int) -> int:
    poh = _poh_params(state)
    v = poh.get(key)
    try:
        return int(v)
    except Exception:
        return int(default)


def _param_float(state: Json, key: str, default: float) -> float:
    poh = _poh_params(state)
    v = poh.get(key)
    try:
        return float(v)
    except Exception:
        return float(default)


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


def _case_ready_to_finalize(case: Json, *, min_total: int, pass_threshold: int, fail_max: int) -> bool:
    """Heuristic: enqueue finalize when the case looks ready.

    The apply-layer is authoritative. Scheduler only tries to reduce latency.

    Readiness rules (deterministic, based on chain state only):
      - If fails > fail_max -> ready (early fail possible)
      - Else if total_reviews >= min_total -> ready (final decision can be made)
    """

    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized", "rejected"):
        return False

    jm = case.get("jurors")
    if not isinstance(jm, dict) or len(jm) == 0:
        return False

    passes = 0
    fails = 0
    total = 0
    for _jid, jrec_any in jm.items():
        jrec = _as_dict(jrec_any)
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v not in ("pass", "fail"):
            continue
        total += 1
        if v == "pass":
            passes += 1
        else:
            fails += 1

    if fails > max(0, int(fail_max)):
        return True

    if total >= max(0, int(min_total)):
        # even if not enough passes, finalize can mark rejected deterministically
        return True

    # Optional: if passes already meet threshold and min_total is also met.
    if total >= max(0, int(min_total)) and passes >= max(0, int(pass_threshold)):
        return True

    return False


def _case_needs_receipt(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    if _as_str(case.get("tier2_receipt_emitted") or "").strip().lower() == "true":
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    return status in ("awarded", "rejected")


def schedule_poh_tier2_system_txs(state: Json, *, next_height: int) -> int:
    """Block-path automation for Tier 2.

    Production intent:
      - Tier1 user can request Tier2 by submitting a short video.
      - Jurors swipe in a gated feed. On-chain records attestations.
      - After enough attestations, system finalizes and emits a receipt.

    Defaults (override via env vars):
      - WEALL_POH_TIER2_N_JURORS=25
      - WEALL_POH_TIER2_MIN_TOTAL_REVIEWS=25
      - WEALL_POH_TIER2_PASS_THRESHOLD=20
      - WEALL_POH_TIER2_FAIL_MAX=3
      - WEALL_POH_TIER2_MIN_REP=0.0

    Returns number of system txs enqueued (best-effort, dedupe-safe).
    """

    enq = 0

    n_jurors = max(1, _param_int(state, "tier2_n_jurors", _env_int("WEALL_POH_TIER2_N_JURORS", 25)))
    min_total = max(1, _param_int(state, "tier2_min_total_reviews", _env_int("WEALL_POH_TIER2_MIN_TOTAL_REVIEWS", 25)))
    pass_threshold = max(1, _param_int(state, "tier2_pass_threshold", _env_int("WEALL_POH_TIER2_PASS_THRESHOLD", 20)))
    fail_max = max(0, _param_int(state, "tier2_fail_max", _env_int("WEALL_POH_TIER2_FAIL_MAX", 3)))

    min_rep = _param_float(state, "tier2_min_rep", _env_float("WEALL_POH_TIER2_MIN_REP", 0.0))

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

                    jurors = pick_tier2_jurors(
                        state=state,
                        case_id=cid,
                        target_account=account_id,
                        n_jurors=int(n_jurors),
                        min_rep=float(min_rep),
                    )
                except Exception:
                    jurors = []

                if isinstance(jurors, list) and len(jurors) == int(n_jurors):
                    enqueue_system_tx(
                        state,
                        tx_type="POH_TIER2_JUROR_ASSIGN",
                        payload={"case_id": cid, "jurors": jurors, "n_jurors": int(n_jurors)},
                        due_height=int(next_height),
                        signer="SYSTEM",
                        once=True,
                        parent=None,
                        phase="post",
                    )
                    enq += 1

        # FINALIZE
        if _case_ready_to_finalize(case, min_total=min_total, pass_threshold=pass_threshold, fail_max=fail_max):
            enqueue_system_tx(
                state,
                tx_type="POH_TIER2_FINALIZE",
                payload={
                    "case_id": cid,
                    "ts_ms": 0,
                    "min_total_reviews": int(min_total),
                    "pass_threshold": int(pass_threshold),
                    "fail_max": int(fail_max),
                },
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enq += 1

            # Receipt matches canon (parent auto-filled as POH_TIER2_FINALIZE)
            enqueue_system_tx(
                state,
                tx_type="POH_TIER2_RECEIPT",
                payload={"case_id": cid, "receipt_id": f"poh2rcpt:{cid}", "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent="POH_TIER2_FINALIZE",
                phase="post",
            )
            enq += 1

        # If a finalize happened previously but receipt hasn't been emitted (catch-up)
        if _case_needs_receipt(case):
            enqueue_system_tx(
                state,
                tx_type="POH_TIER2_RECEIPT",
                payload={"case_id": cid, "receipt_id": f"poh2rcpt:{cid}", "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent="POH_TIER2_FINALIZE",
                phase="post",
            )
            enq += 1

    return enq
