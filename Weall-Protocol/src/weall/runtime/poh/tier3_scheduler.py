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


def _tier3_cases(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    cases = poh.get("tier3_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["tier3_cases"] = cases
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


def _case_needs_auto_attendance(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("init", "open"):
        return False
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        return False
    # if any juror has attendance unset, we can mark it (MVP automation)
    for _jid, jrec in jm.items():
        if isinstance(jrec, dict) and jrec.get("attended") is None:
            return True
    return False


def _case_needs_finalize(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("init", "open"):
        return False
    jm = case.get("jurors")
    if not isinstance(jm, dict) or len(jm) != 10:
        return False

    # finalize requires: all attending marked, and interacting verdicts present
    # (apply layer enforces the exact conditions; we enqueue when it looks ready)
    attended_ok = True
    for _jid, jrec_any in jm.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        if jrec.get("attended") is None:
            attended_ok = False
            break

    if not attended_ok:
        return False

    # verdicts from interacting jurors (3)
    have_verdicts = 0
    for _jid, jrec_any in jm.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        if _as_str(jrec.get("role") or "") != "interacting":
            continue
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v in ("pass", "fail"):
            have_verdicts += 1
    return have_verdicts == 3


def schedule_poh_tier3_system_txs(state: Json, *, next_height: int) -> int:
    """
    Enqueue system txs needed to progress Tier3 cases.

    Current MVP automations:
      - Assign jurors for new cases (deterministic)
      - Auto mark attendance for all jurors (placeholder for oracle / live system)
      - Finalize case if ready

    Returns number of enqueued system txs.
    """
    enq = 0
    cases = _tier3_cases(state)

    min_rep = 0.0
    try:
        min_rep = float(os.environ.get("WEALL_POH_TIER3_MIN_REP", "0.0"))
    except Exception:
        min_rep = 0.0

    for case_id, case in list(cases.items()):
        if not isinstance(case, dict):
            continue

        cid = _as_str(case.get("case_id") or case_id).strip() or _as_str(case_id).strip()
        if not cid:
            continue

        # ASSIGN (once)
        if _case_needs_assign(case):
            account_id = _as_str(case.get("account_id") or "").strip()
            if account_id:
                try:
                    from weall.runtime.poh.juror_select import pick_tier3_jurors  # type: ignore

                    interacting, observing = pick_tier3_jurors(
                        state=state,
                        case_id=cid,
                        target_account=account_id,
                        n_interacting=3,
                        n_observing=7,
                        min_rep=min_rep,
                    )
                    jurors = list(interacting) + list(observing)
                except Exception:
                    jurors = []

                if isinstance(jurors, list) and len(jurors) == 10:
                    enqueue_system_tx(
                        state,
                        tx_type="POH_TIER3_JUROR_ASSIGN",
                        payload={"case_id": cid, "jurors": jurors},
                        due_height=int(next_height),
                        signer="SYSTEM",
                        once=True,
                        parent=None,
                        phase="post",
                    )
                    enq += 1

        # 1) auto attendance (placeholder)
        if _case_needs_auto_attendance(case):
            jm = case.get("jurors")
            if isinstance(jm, dict):
                for jid, jrec_any in jm.items():
                    if not isinstance(jrec_any, dict):
                        continue
                    if jrec_any.get("attended") is not None:
                        continue
                    enqueue_system_tx(
                        state,
                        tx_type="POH_TIER3_ATTENDANCE_MARK",
                        payload={"case_id": cid, "juror_id": _as_str(jid).strip(), "attended": True, "ts_ms": 0},
                        due_height=int(next_height),
                        signer="SYSTEM",
                        once=True,
                        parent=None,
                        phase="post",
                    )
                    enq += 1

        # 2) finalize when ready
        if _case_needs_finalize(case):
            enqueue_system_tx(
                state,
                tx_type="POH_TIER3_FINALIZE",
                payload={"case_id": cid, "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enq += 1

            # 3) receipt (optional, but matches canon)
            enqueue_system_tx(
                state,
                tx_type="POH_TIER3_RECEIPT",
                payload={"case_id": cid, "receipt_id": f"poh3rcpt:{cid}", "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enq += 1

    return enq

