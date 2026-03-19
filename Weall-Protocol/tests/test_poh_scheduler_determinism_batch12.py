from __future__ import annotations

from typing import Any, Dict

from weall.runtime.poh.juror_select import eligible_tier2_jurors, eligible_tier3_jurors
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.poh.tier3_scheduler import schedule_poh_tier3_system_txs

Json = Dict[str, Any]


def _tier2_state() -> Json:
    return {
        "height": 11,
        "tip": "b" * 64,
        "accounts": {
            "@target": {"poh_tier": 1, "reputation_milli": 0},
            "@j1": {"poh_tier": 3, "reputation_milli": 5000},
            "@j2": {"poh_tier": 3, "reputation_milli": 5000},
            "@j3": {"poh_tier": 3, "reputation_milli": 5000},
        },
        "params": {
            "poh": {
                "tier2_n_jurors": 3,
                "tier2_min_total_reviews": 3,
                "tier2_pass_threshold": 2,
                "tier2_fail_max": 1,
                "tier2_min_rep_milli": 0,
            }
        },
        "poh": {
            "tier2_cases": {
                "case-1": {
                    "case_id": "case-1",
                    "account_id": "@target",
                    "status": "open",
                    "jurors": {},
                }
            }
        },
    }


def _tier3_state() -> Json:
    return {
        "height": 22,
        "tip": "c" * 64,
        "accounts": {
            "@target": {"poh_tier": 2, "reputation_milli": 0},
            **{f"@j{i}": {"poh_tier": 3, "reputation_milli": 5000} for i in range(1, 12)},
        },
        "params": {"poh": {"tier3_min_rep_milli": 0}},
        "poh": {
            "tier3_cases": {
                "case-3": {
                    "case_id": "case-3",
                    "account_id": "@target",
                    "status": "open",
                    "jurors": {},
                }
            }
        },
    }


def test_tier2_scheduler_is_env_independent(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_POH_TIER2_N_JURORS", "99")
    monkeypatch.setenv("WEALL_POH_TIER2_MIN_TOTAL_REVIEWS", "99")
    monkeypatch.setenv("WEALL_POH_TIER2_PASS_THRESHOLD", "99")
    monkeypatch.setenv("WEALL_POH_TIER2_FAIL_MAX", "99")
    monkeypatch.setenv("WEALL_POH_TIER2_MIN_REP", "9.999")

    state = _tier2_state()
    enq = schedule_poh_tier2_system_txs(state, next_height=12)

    assert enq == 1
    queue = (state.get("system_queue") or [])
    assert len(queue) == 1
    payload = dict(queue[0].get("payload") or {})
    assert payload["n_jurors"] == 3
    assert payload["min_total_reviews"] == 3
    assert payload["pass_threshold"] == 2
    assert payload["fail_max"] == 1
    assert payload["min_rep_milli"] == 0


def test_tier3_scheduler_is_env_independent(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_POH_TIER3_MIN_REP", "9.999")

    state = _tier3_state()
    enq = schedule_poh_tier3_system_txs(state, next_height=23)

    assert enq == 1
    queue = (state.get("system_queue") or [])
    assert len(queue) == 1
    assert queue[0].get("tx_type") == "POH_TIER3_JUROR_ASSIGN"
    payload = dict(queue[0].get("payload") or {})
    jurors = list(payload.get("jurors") or [])
    assert len(jurors) == 10
    assert payload["min_rep_milli"] == 0


def test_legacy_float_thresholds_are_converted_once_to_integer_units() -> None:
    tier2_state = _tier2_state()
    tier2_state["params"]["poh"].pop("tier2_min_rep_milli", None)
    tier2_state["params"]["poh"]["tier2_min_rep"] = "5.0"
    assert eligible_tier2_jurors(state=tier2_state, min_rep_units=5000) == ["@j1", "@j2", "@j3"]
    assert eligible_tier2_jurors(state=tier2_state, min_rep="5.0") == ["@j1", "@j2", "@j3"]

    tier3_state = _tier3_state()
    expected_tier3 = sorted([f"@j{i}" for i in range(1, 12)])
    assert eligible_tier3_jurors(state=tier3_state, min_rep_units=5000) == expected_tier3
    assert eligible_tier3_jurors(state=tier3_state, min_rep="5.0") == expected_tier3


def test_scheduler_uses_integer_rep_threshold_payloads_for_legacy_thresholds() -> None:
    state = _tier2_state()
    state["params"]["poh"].pop("tier2_min_rep_milli", None)
    state["params"]["poh"]["tier2_min_rep"] = "5.0"

    enq = schedule_poh_tier2_system_txs(state, next_height=12)

    assert enq == 1
    payload = dict((state.get("system_queue") or [])[0].get("payload") or {})
    assert payload["min_rep_milli"] == 5000

    state3 = _tier3_state()
    state3["params"]["poh"].pop("tier3_min_rep_milli", None)
    state3["params"]["poh"]["tier3_min_rep"] = "5.0"

    enq3 = schedule_poh_tier3_system_txs(state3, next_height=23)

    assert enq3 == 1
    payload3 = dict((state3.get("system_queue") or [])[0].get("payload") or {})
    assert payload3["min_rep_milli"] == 5000
