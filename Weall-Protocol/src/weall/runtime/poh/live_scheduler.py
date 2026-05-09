from __future__ import annotations

import hashlib
from typing import Any

from weall.runtime.reputation_units import threshold_to_units
from weall.runtime.poh.live_quorum import (
    DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR,
    DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR,
    MAX_LIVE_INTERACTING_JURORS,
    MAX_LIVE_JURORS,
    live_quorum_summary,
)
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]

DEFAULT_LIVE_MIN_REP_UNITS = 0


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


def _params_root(state: Json) -> Json:
    params = state.get("params")
    return params if isinstance(params, dict) else {}


def _poh_params(state: Json) -> Json:
    params = _params_root(state)
    poh = params.get("poh")
    return poh if isinstance(poh, dict) else {}



def _param_int(state: Json, *, key: str, default: int) -> int:
    poh = _poh_params(state)
    try:
        return int(poh.get(key, default))
    except Exception:
        return int(default)

def _param_rep_units(state: Json, *, units_key: str, legacy_key: str, default_units: int) -> int:
    poh = _poh_params(state)
    raw_units = poh.get(units_key)
    try:
        return max(0, int(raw_units))
    except Exception:
        pass
    return max(0, threshold_to_units(poh.get(legacy_key), default=default_units))




def _param_bool_any(state: Json, *, keys: tuple[str, ...], default: bool = False) -> bool:
    params = _params_root(state)
    poh = _poh_params(state)
    for key in keys:
        raw = poh.get(key) if key in poh else params.get(key)
        if raw is None:
            continue
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off"}:
            return False
    return bool(default)


def _param_int_any(state: Json, *, keys: tuple[str, ...], default: int = 0) -> int:
    params = _params_root(state)
    poh = _poh_params(state)
    for key in keys:
        raw = poh.get(key) if key in poh else params.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except Exception:
            continue
    return int(default)


def _live_partial_panels_allowed(state: Json, *, next_height: int) -> bool:
    """Return true only when partial Live panels are chain-authorized.

    Partial Live PoH panels are useful for genesis bootstrap, but they must not
    silently become the permanent security denominator. The permission is read
    only from committed params, never local env.
    """

    explicit = _param_bool_any(
        state,
        keys=("live_partial_panels_enabled", "poh_live_partial_panels_enabled"),
        default=False,
    )
    bootstrap_mode = _as_str(_params_root(state).get("poh_bootstrap_mode") or "").strip().lower()
    bootstrap_enabled = bootstrap_mode in {"open", "allowlist", "genesis", "bootstrap"}
    if not explicit and not bootstrap_enabled:
        return False
    until = _param_int_any(
        state,
        keys=(
            "live_partial_until_height",
            "poh_live_partial_until_height",
            "bootstrap_expires_height",
        ),
        default=0,
    )
    if until <= 0:
        return bool(explicit)
    return int(next_height) <= int(until)

def _session_commitment(state: Json, *, case_id: str, account_id: str, case: Json | None = None) -> str:
    # Dedicated Live requests must provide a session commitment up front.  Keep
    # the deterministic fallback for legacy in-memory fixtures only; strict
    # apply-layer validation will reject missing case commitments before init or
    # assignment can affect canonical state.
    if isinstance(case, dict):
        existing = _as_str(case.get("session_commitment") or "").strip()
        if existing:
            return existing
    tip = _as_str(state.get("tip") or "").strip()
    height = _as_int(state.get("height") or 0)
    seed = f"{tip}|{height}|{case_id}|{account_id}|POH_LIVE".encode()
    return hashlib.sha256(seed).hexdigest()


def _live_commitment_payload(case: Json) -> Json:
    out: Json = {}
    for key in (
        "session_commitment",
        "room_commitment",
        "prompt_commitment",
        "device_pairing_commitment",
        "relay_commitment",
    ):
        value = _as_str(case.get(key) or "").strip() if isinstance(case, dict) else ""
        if value:
            out[key] = value
    return out


def _live_cases(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    cases = poh.get("live_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["live_cases"] = cases
    return cases


def _case_needs_init(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status != "requested":
        return False
    return case.get("init_ts_ms") is None


def _case_needs_assign(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("open", "init"):
        return False
    jm = case.get("jurors")
    if not isinstance(jm, dict) or len(jm) == 0:
        return True
    return False


def _case_needs_finalize(case: Json) -> bool:
    if not isinstance(case, dict):
        return False
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("init", "open"):
        return False
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        return False

    active = []
    for _jid, jrec_any in jm.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        if bool(jrec.get("replaced", False)):
            continue
        if _as_str(jrec.get("role") or "") == "interacting":
            active.append(jrec)

    if not active or len(active) > MAX_LIVE_INTERACTING_JURORS:
        return False

    # Observers/watchers are audit witnesses and may attend, but they do not
    # block finalization. The active reviewer set is the n-of-m decision set.
    have_verdicts = 0
    for jrec in active:
        if jrec.get("accepted") is not True or jrec.get("attended") is not True:
            return False
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v in ("pass", "fail"):
            have_verdicts += 1
    return have_verdicts == len(active)


def schedule_poh_live_system_txs(state: Json, *, next_height: int) -> int:
    """Enqueue system txs needed to progress Live cases.

    Production correctness:
      - This scheduler must NOT fabricate attendance or verdicts.
      - Attendance marks and verdict submissions must come from real txs.
      - The scheduler only progresses deterministic, system-owned steps.

    Live lifecycle:
      - POH_LIVE_SESSION_INIT: opens the on-chain case (session anchor)
      - POH_LIVE_JUROR_ASSIGN: assigns jurors
      - POH_LIVE_FINALIZE: finalizes if attendance+verdicts are ready
      - POH_LIVE_RECEIPT: receipt-only marker

    Returns number of enqueued system txs.
    """

    enq = 0
    cases = _live_cases(state)

    min_rep_units = _param_rep_units(
        state,
        units_key="live_min_rep_milli",
        legacy_key="live_min_rep",
        default_units=DEFAULT_LIVE_MIN_REP_UNITS,
    )

    for case_id, case in list(cases.items()):
        if not isinstance(case, dict):
            continue

        cid = _as_str(case.get("case_id") or case_id).strip() or _as_str(case_id).strip()
        if not cid:
            continue

        account_id = _as_str(case.get("account_id") or "").strip()

        # INIT (once) for requested cases
        if _case_needs_init(case):
            if account_id:
                payload = {
                    "case_id": cid,
                    "account_id": account_id,
                    "session_commitment": _session_commitment(
                        state, case_id=cid, account_id=account_id, case=case
                    ),
                    "ts_ms": 0,
                }
                payload.update(_live_commitment_payload(case))
                enqueue_system_tx(
                    state,
                    tx_type="POH_LIVE_SESSION_INIT",
                    payload=payload,
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=None,
                    phase="post",
                )
                enq += 1

        # ASSIGN (once)
        if _case_needs_assign(case):
            if account_id:
                try:
                    from weall.runtime.poh.juror_select import pick_live_jurors  # type: ignore

                    interacting, observing = pick_live_jurors(
                        state=state,
                        case_id=cid,
                        target_account=account_id,
                        n_interacting=MAX_LIVE_INTERACTING_JURORS,
                        n_observing=MAX_LIVE_JURORS - MAX_LIVE_INTERACTING_JURORS,
                        min_rep_units=int(min_rep_units),
                        allow_partial=_live_partial_panels_allowed(state, next_height=int(next_height)),
                    )
                    jurors = list(interacting) + list(observing)
                except Exception:
                    jurors = []

                if isinstance(jurors, list) and 1 <= len(jurors) <= MAX_LIVE_JURORS:
                    pass_num = _param_int(
                        state,
                        key="live_pass_threshold_num",
                        default=DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR,
                    )
                    pass_den = _param_int(
                        state,
                        key="live_pass_threshold_den",
                        default=DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR,
                    )
                    enqueue_system_tx(
                        state,
                        tx_type="POH_LIVE_JUROR_ASSIGN",
                        payload={
                            "case_id": cid,
                            "jurors": jurors,
                            "min_rep_milli": int(min_rep_units),
                            "live_quorum": live_quorum_summary(
                                panel_size=len(jurors),
                                numerator=pass_num,
                                denominator=pass_den,
                            ),
                        },
                        due_height=int(next_height),
                        signer="SYSTEM",
                        once=True,
                        parent="POH_LIVE_SESSION_INIT",
                        phase="post",
                    )
                    enq += 1

        # Finalize + receipt
        if _case_needs_finalize(case):
            enqueue_system_tx(
                state,
                tx_type="POH_LIVE_FINALIZE",
                payload={"case_id": cid, "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enq += 1

            enqueue_system_tx(
                state,
                tx_type="POH_LIVE_RECEIPT",
                payload={"case_id": cid, "receipt_id": f"poh_live_rcpt:{cid}", "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent="POH_LIVE_FINALIZE",
                phase="post",
            )
            enq += 1

    return enq
