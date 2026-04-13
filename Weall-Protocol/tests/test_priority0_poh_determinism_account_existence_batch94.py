from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {},
        "params": {"system_signer": "SYSTEM", "poh_bootstrap_open": False},
        "poh": {},
        "roles": {},
    }


def _tx(tx_type: str, *, signer: str = "alice", system: bool = False, nonce: int = 1, payload: dict | None = None) -> dict:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        system=system,
        payload=payload or {"account_id": "alice"},
    ).to_json()


@pytest.mark.parametrize(
    ("tx_type", "payload", "expected_reason"),
    [
        ("POH_TIER_SET", {"account_id": "alice", "tier": 2, "_system": True}, "account_not_registered"),
        ("POH_TIER2_REQUEST_OPEN", {"account_id": "alice", "video_commitment": "v1"}, "account_not_registered"),
    ],
)
def test_poh_apply_requires_registered_subject_account_for_consensus_visible_mutations(
    tx_type: str, payload: dict, expected_reason: str
) -> None:
    state = _state()
    payload = dict(payload)
    system = bool(payload.pop("_system", False))

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _tx(tx_type, payload=payload, system=system, signer="SYSTEM" if system else "alice", nonce=0 if system else 1))

    assert excinfo.value.reason == expected_reason


def test_poh_tier2_finalize_does_not_auto_create_missing_account() -> None:
    state = _state()
    state["poh"] = {
        "tier2_cases": {
            "case-1": {
                "case_id": "case-1",
                "account_id": "alice",
                "status": "assigned",
                "jurors": {
                    f"j{i}": {"verdict": "pass", "ts_ms": i} for i in range(25)
                },
                "min_total_reviews": 25,
                "pass_threshold": 20,
                "fail_max": 3,
            }
        }
    }

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx(
                "POH_TIER2_FINALIZE",
                signer="SYSTEM",
                system=True,
                nonce=0,
                payload={"case_id": "case-1", "ts_ms": 123},
            ),
        )

    assert excinfo.value.reason == "account_not_registered"


def test_poh_tier3_finalize_does_not_auto_create_missing_account() -> None:
    state = _state()
    state["poh"] = {
        "tier3_cases": {
            "case-3": {
                "case_id": "case-3",
                "account_id": "alice",
                "status": "open",
                "jurors": {
                    "j0": {"role": "interacting", "attended": True, "verdict": "pass"},
                    "j1": {"role": "interacting", "attended": True, "verdict": "pass"},
                    "j2": {"role": "interacting", "attended": True, "verdict": "fail"},
                    **{f"j{i}": {"role": "observing", "attended": True, "verdict": None} for i in range(3, 10)},
                },
            }
        }
    }

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx(
                "POH_TIER3_FINALIZE",
                signer="SYSTEM",
                system=True,
                nonce=0,
                payload={"case_id": "case-3", "ts_ms": 123},
            ),
        )

    assert excinfo.value.reason == "account_not_registered"
