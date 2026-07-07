from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "SYSTEM",
    nonce: int = 1,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def test_validator_set_update_can_stage_future_epoch_activation() -> None:
    st: dict = {}

    meta = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2", "v2"], "activate_at_epoch": 2},
            nonce=1,
            system=True,
        ),
    )

    assert meta and meta["applied"] == "VALIDATOR_SET_UPDATE"
    assert meta["pending"] is True
    assert meta["activate_at_epoch"] == 2
    assert st.get("roles", {}).get("validators", {}).get("active_set") in (None, [])
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["active_set"] == ["v1", "v2"]
    assert pending["activate_at_epoch"] == 2


def test_epoch_open_activates_pending_validator_set_exactly_at_boundary() -> None:
    st: dict = {}

    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2", "v3"], "activate_at_epoch": 2},
            nonce=1,
            system=True,
        ),
    )

    meta1 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=2, system=True))
    assert meta1 and meta1["applied"] == "EPOCH_OPEN"
    assert "validator_set_activated" not in meta1
    assert st.get("roles", {}).get("validators", {}).get("active_set") in (None, [])

    close1 = apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=3, system=True))
    assert close1 and close1["applied"] == "EPOCH_CLOSE"

    meta2 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=4, system=True))
    assert meta2 and meta2["applied"] == "EPOCH_OPEN"
    activated = meta2.get("validator_set_activated")
    assert isinstance(activated, dict)
    assert activated["active_set"] == ["v1", "v2", "v3"]
    assert activated["activate_at_epoch"] == 2
    assert st["roles"]["validators"]["active_set"] == ["v1", "v2", "v3"]
    assert st["consensus"]["validator_set"]["epoch"] == 1
    assert "pending" not in st["consensus"]["validator_set"]


def test_validator_set_update_rejects_non_future_activation_epoch() -> None:
    st: dict = {}

    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=1, system=True))
    apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=2, system=True))
    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=3, system=True))

    with pytest.raises(ApplyError):
        apply_tx(
            st,
            _env(
                "VALIDATOR_SET_UPDATE",
                {"active_set": ["v1", "v2"], "activate_at_epoch": 2},
                nonce=4,
                system=True,
            ),
        )
