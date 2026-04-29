from __future__ import annotations

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _ledger(*, system_signer: str = "SYSTEM", open_mode: bool = False) -> dict:
    params = {"system_signer": system_signer}
    if open_mode:
        params["poh_bootstrap_open"] = True
        params["poh_bootstrap_max_height"] = 50
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 0},
        },
        "params": params,
        "poh": {},
        "roles": {},
    }


def _env(*, signer: str, system: bool, payload: dict | None = None) -> dict:
    return TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer=signer,
        nonce=1,
        system=system,
        payload=payload or {"account_id": "alice"},
    ).to_json()


def test_public_ingress_rejects_configured_system_signer_alias() -> None:
    ledger = _ledger(system_signer="CHAIN_SYSTEM")
    verdict = admit_tx(
        _env(signer="CHAIN_SYSTEM", system=True),
        ledger,
        context="mempool",
    )
    assert verdict.ok is False
    assert verdict.rejection is not None
    assert verdict.rejection.reason == "system_only_tx_not_allowed_in_public_ingress"


def test_block_admission_rejects_noncanonical_system_alias_even_with_system_flag() -> None:
    ledger = _ledger(system_signer="CHAIN_SYSTEM")
    verdict = admit_tx(
        _env(signer="SYSTEM", system=True),
        ledger,
        context="block",
    )
    assert verdict.ok is False
    assert verdict.rejection is not None
    assert verdict.rejection.reason == "system_signer_required"


def test_apply_rejects_noncanonical_system_alias_on_allowlist_path() -> None:
    state = _ledger(system_signer="CHAIN_SYSTEM")
    state["params"]["bootstrap_allowlist"] = {"alice": {}}
    state["params"]["bootstrap_expires_height"] = 50

    try:
        apply_tx(
            state,
            _env(
                signer="SYSTEM",
                system=True,
                payload={"account_id": "alice"},
            ),
        )
    except ApplyError as exc:
        assert exc.reason == "system_signer_required"
    else:
        raise AssertionError("expected ApplyError")


def test_open_mode_still_allows_self_bootstrap_without_system_flag() -> None:
    state = _ledger(system_signer="CHAIN_SYSTEM", open_mode=True)
    apply_tx(
        state,
        _env(
            signer="alice",
            system=False,
            payload={"account_id": "alice"},
        ),
    )
    acct = state["accounts"]["alice"]
    assert acct["poh_tier"] == 3
    assert acct["poh_bootstrap_mode"] == "open"

