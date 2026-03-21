from __future__ import annotations

import pytest

from weall.runtime.bft_hotstuff import CONSENSUS_PHASE_BFT_ACTIVE
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


def test_pending_validator_set_survives_intermediate_epoch_boundaries_until_exact_activation() -> None:
    st: dict = {}

    stage = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v4", "v2", "v1", "v3"], "activate_at_epoch": 3},
            nonce=1,
            system=True,
        ),
    )
    assert stage and stage["pending"] is True
    assert st["consensus"]["validator_set"]["pending"]["active_set"] == ["v1", "v2", "v3", "v4"]

    open1 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=2, system=True))
    assert open1 == {"applied": "EPOCH_OPEN", "epoch": 1}
    apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=3, system=True))

    open2 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=4, system=True))
    assert open2 == {"applied": "EPOCH_OPEN", "epoch": 2}
    roles = st.get("roles") if isinstance(st.get("roles"), dict) else {}
    validators = roles.get("validators") if isinstance(roles.get("validators"), dict) else {}
    assert validators.get("active_set", []) == []
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["activate_at_epoch"] == 3
    assert pending["active_set"] == ["v1", "v2", "v3", "v4"]

    apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 2}, nonce=5, system=True))
    open3 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 3}, nonce=6, system=True))
    activated = open3.get("validator_set_activated") if open3 else None

    assert isinstance(activated, dict)
    assert activated["activate_at_epoch"] == 3
    assert activated["active_set"] == ["v1", "v2", "v3", "v4"]
    assert activated["validator_epoch"] == 1
    assert st["roles"]["validators"]["active_set"] == ["v1", "v2", "v3", "v4"]
    assert st["consensus"]["validator_set"]["active_set"] == ["v1", "v2", "v3", "v4"]
    assert "pending" not in st["consensus"]["validator_set"]


def test_pending_bft_activation_promotes_phase_and_records_transition_at_boundary() -> None:
    st: dict = {}

    stage = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {
                "active_set": ["v4", "v2", "v1", "v3"],
                "activate_at_epoch": 2,
                "activate_bft_at_epoch": 2,
            },
            nonce=1,
            system=True,
        ),
    )
    assert stage and stage["consensus_phase"] == CONSENSUS_PHASE_BFT_ACTIVE
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["phase"] == CONSENSUS_PHASE_BFT_ACTIVE

    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=2, system=True))
    apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=3, system=True))
    open2 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=4, system=True))

    activated = open2.get("validator_set_activated") if open2 else None
    assert isinstance(activated, dict)
    assert activated["consensus_phase"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert st["consensus"]["phase"]["current"] == CONSENSUS_PHASE_BFT_ACTIVE
    history = st["consensus"]["phase"]["history"]
    assert isinstance(history, list) and history
    assert history[-1]["reason"] == "validator_set_activation"
    assert history[-1]["to"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert history[-1]["activation_epoch"] == 2


def test_same_pending_validator_set_cannot_be_restaged_with_conflicting_phase() -> None:
    st: dict = {}

    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v4", "v2", "v1", "v3"], "activate_at_epoch": 2},
            nonce=1,
            system=True,
        ),
    )

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            st,
            _env(
                "VALIDATOR_SET_UPDATE",
                {
                    "active_set": ["v1", "v2", "v3", "v4"],
                    "activate_at_epoch": 2,
                    "activate_bft_at_epoch": 2,
                },
                nonce=2,
                system=True,
            ),
        )

    assert excinfo.value.reason == "validator_set_pending_phase_conflict"


def test_same_pending_bft_validator_set_can_be_restaged_idempotently() -> None:
    st: dict = {}

    meta1 = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {
                "active_set": ["v4", "v2", "v1", "v3"],
                "activate_at_epoch": 2,
                "activate_bft_at_epoch": 2,
            },
            nonce=1,
            system=True,
        ),
    )
    meta2 = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {
                "active_set": ["v1", "v2", "v3", "v4"],
                "activate_at_epoch": 2,
                "activate_bft_at_epoch": 2,
            },
            nonce=2,
            system=True,
        ),
    )

    assert meta1 and meta2
    assert meta1["validator_set_hash"] == meta2["validator_set_hash"]
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["phase"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert pending["active_set"] == ["v1", "v2", "v3", "v4"]
