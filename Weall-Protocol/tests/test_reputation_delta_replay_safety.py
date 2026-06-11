from __future__ import annotations

from weall.runtime.apply.reputation import apply_reputation, apply_reputation_delta_system
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=system,
        parent=parent,
    )


def _state() -> dict:
    return {
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation_milli": 0,
            }
        }
    }


def test_reputation_delta_apply_duplicate_id_is_score_noop() -> None:
    state = _state()
    payload = {
        "account_id": "@alice",
        "delta": 1,
        "delta_id": "rep:test:duplicate",
        "reason": "test_positive_delta",
    }

    first = apply_reputation(
        state,
        _env(
            "REPUTATION_DELTA_APPLY",
            "SYSTEM",
            1,
            payload,
            system=True,
            parent="test:parent",
        ),
    )
    assert first["deduped"] is False
    assert first["reputation_milli"] == 1000
    assert state["accounts"]["@alice"]["reputation_milli"] == 1000

    second = apply_reputation(
        state,
        _env(
            "REPUTATION_DELTA_APPLY",
            "SYSTEM",
            2,
            payload,
            system=True,
            parent="test:parent",
        ),
    )
    assert second["deduped"] is True
    assert second["reputation_milli"] == 1000
    assert state["accounts"]["@alice"]["reputation_milli"] == 1000
    assert len(state["reputation"]["deltas"]) == 1


def test_reputation_delta_apply_delta_milli_is_not_scaled_again() -> None:
    state = _state()

    result = apply_reputation(
        state,
        _env(
            "REPUTATION_DELTA_APPLY",
            "SYSTEM",
            1,
            {
                "account_id": "@alice",
                "delta_milli": 1000,
                "delta_id": "rep:test:delta-milli",
                "reason": "test_delta_milli_units",
            },
            system=True,
            parent="test:parent",
        ),
    )

    assert result["reputation_milli"] == 1000
    assert state["accounts"]["@alice"]["reputation_milli"] == 1000
    assert state["reputation"]["deltas"][0]["delta"] == 1.0
    assert state["reputation"]["deltas"][0]["delta_milli"] == 1000


def test_reputation_delta_apply_negative_delta_milli_is_not_auto_ban_scale_bug() -> None:
    state = _state()

    result = apply_reputation(
        state,
        _env(
            "REPUTATION_DELTA_APPLY",
            "SYSTEM",
            1,
            {
                "account_id": "@alice",
                "delta_milli": -500,
                "delta_id": "rep:test:late-withdraw-light-penalty",
                "reason": "late_withdraw_light_penalty",
            },
            system=True,
            parent="test:parent",
        ),
    )

    assert result["reputation_milli"] == -500
    assert result["newly_banned"] is False
    assert state["accounts"]["@alice"]["reputation_milli"] == -500
    assert state["accounts"]["@alice"]["banned"] is False


def test_inline_system_reputation_delta_duplicate_id_is_score_noop() -> None:
    state = _state()
    evidence = {
        "delta_id": "rep:test:inline-system-duplicate",
        "source": "consensus",
        "event": "TEST_EQUIVOCATION",
    }

    first = apply_reputation_delta_system(
        state,
        account_id="@alice",
        delta=-25.0,
        reason="test_inline_system_penalty",
        evidence=evidence,
        at_nonce=10,
    )
    assert first["deduped"] is False
    assert first["reputation_milli"] == -25000
    assert state["accounts"]["@alice"]["reputation_milli"] == -25000

    second = apply_reputation_delta_system(
        state,
        account_id="@alice",
        delta=-25.0,
        reason="test_inline_system_penalty",
        evidence=evidence,
        at_nonce=11,
    )
    assert second["deduped"] is True
    assert second["reputation_milli"] == -25000
    assert state["accounts"]["@alice"]["reputation_milli"] == -25000
    assert len(state["reputation"]["deltas"]) == 1
