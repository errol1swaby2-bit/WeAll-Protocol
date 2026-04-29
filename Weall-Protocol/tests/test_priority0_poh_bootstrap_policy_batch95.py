from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _ledger(
    *,
    open_bootstrap: bool = False,
    max_height: int = 50,
    allowlist: dict | None = None,
    mode: str | None = None,
    height: int = 10,
) -> dict:
    params = {"system_signer": "SYSTEM"}
    if open_bootstrap:
        params["poh_bootstrap_open"] = True
        params["poh_bootstrap_max_height"] = max_height
    if allowlist is not None:
        params["bootstrap_allowlist"] = allowlist
        params["bootstrap_expires_height"] = max_height
    if mode is not None:
        params["poh_bootstrap_mode"] = mode
    return {
        "chain_id": "weall-test",
        "height": height,
        "accounts": {
            "alice": {
                "nonce": 0,
                "pubkey": "alice-pk",
                "pubkeys": ["alice-pk"],
                "poh_tier": 0,
            }
        },
        "params": params,
        "poh": {},
        "roles": {},
    }


def _env(
    *,
    signer: str = "alice",
    system: bool = False,
    payload: dict | None = None,
) -> dict:
    return TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer=signer,
        nonce=1,
        system=system,
        payload=payload or {"account_id": "alice"},
    ).to_json()


def test_apply_open_mode_requires_max_height() -> None:
    state = _ledger(open_bootstrap=False)
    state["params"]["poh_bootstrap_open"] = True
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _env())
    assert excinfo.value.reason == "bootstrap_open_requires_max_height"


def test_apply_allowlist_mode_requires_expiry() -> None:
    state = _ledger(allowlist={"alice": {}})
    del state["params"]["bootstrap_expires_height"]
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                signer="SYSTEM",
                system=True,
                payload={"account_id": "alice"},
            ),
        )
    assert excinfo.value.reason == "bootstrap_allowlist_requires_expiry"


def test_apply_open_mode_grants_and_records_metadata() -> None:
    state = _ledger(open_bootstrap=True, max_height=50)
    apply_tx(state, _env())
    acct = state["accounts"]["alice"]
    assert acct["poh_tier"] == 3
    assert acct["poh_bootstrap_mode"] == "open"
    assert acct["poh_bootstrap_height"] == 10
    assert acct["poh_bootstrap_granted"] is True


def test_apply_allowlist_mode_grants_and_records_metadata() -> None:
    state = _ledger(
        allowlist={"alice": {}},
        max_height=50,
    )
    apply_tx(
        state,
        _env(
            signer="SYSTEM",
            system=True,
            payload={"account_id": "alice"},
        ),
    )
    acct = state["accounts"]["alice"]
    assert acct["poh_tier"] == 3
    assert acct["poh_bootstrap_mode"] == "allowlist"
    assert acct["poh_bootstrap_height"] == 10
    assert acct["poh_bootstrap_granted"] is True


def test_apply_rejects_ambiguous_dual_mode_with_system_path() -> None:
    state = _ledger(open_bootstrap=True, allowlist={"alice": {}})
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                signer="SYSTEM",
                system=True,
                payload={"account_id": "alice"},
            ),
        )
    assert excinfo.value.reason == "bootstrap_mode_conflict"


def test_apply_rejects_when_expired_open_mode() -> None:
    state = _ledger(open_bootstrap=True, max_height=5, height=10)
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _env())
    assert excinfo.value.reason == "bootstrap_expired"


def test_apply_rejects_when_closed_mode_selected() -> None:
    state = _ledger(open_bootstrap=False, mode="closed")
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _env(
                signer="SYSTEM",
                system=True,
                payload={"account_id": "alice"},
            ),
        )
    assert excinfo.value.reason == "bootstrap_closed"
