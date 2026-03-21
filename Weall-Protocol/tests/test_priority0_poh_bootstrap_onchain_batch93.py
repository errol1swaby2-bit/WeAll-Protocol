from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _canon() -> TxIndex:
    here = Path(__file__).resolve()
    for root in [here.parent, *here.parents]:
        cand = root / "generated" / "tx_index.json"
        if cand.exists():
            return TxIndex.load_from_file(cand)
    return TxIndex.load_from_file(Path("generated/tx_index.json"))


def _ledger(*, open_bootstrap: bool = False) -> dict:
    return {
        "chain_id": "weall-test",
        "height": 5,
        "accounts": {
            "alice": {
                "nonce": 0,
                "poh_tier": 0,
                "keys": {"alice-pk": {"pubkey": "alice-pk", "active": True}},
            }
        },
        "params": {
            "system_signer": "sys",
            "bootstrap_allowlist": {},
            "bootstrap_expires_height": 100,
            "poh_bootstrap_max_height": 100,
            "poh_bootstrap_open": open_bootstrap,
        },
        "roles": {},
        "poh": {},
    }


def _env(*, signer: str = "alice", system: bool = False) -> dict:
    return TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer=signer,
        nonce=1,
        payload={"account_id": "alice"},
        system=system,
    ).to_json()


def test_admission_rejects_open_bootstrap_when_only_local_env_requests_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_OPEN", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")

    verdict = admit_tx(_env(), _ledger(open_bootstrap=False), _canon(), context="local")

    assert not verdict.ok
    assert verdict.rejection is not None
    assert verdict.rejection.code == "gate_denied"
    assert "Validator" in str(verdict.rejection.reason)


def test_admission_accepts_open_bootstrap_when_enabled_in_ledger_state() -> None:
    verdict = admit_tx(_env(), _ledger(open_bootstrap=True), _canon(), context="local")

    assert verdict.ok
    assert verdict.rejection is None


def test_apply_rejects_local_env_only_bootstrap_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_OPEN", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(_ledger(open_bootstrap=False), _env())

    assert excinfo.value.reason == "system_flag_required"


def test_apply_accepts_onchain_open_bootstrap_and_mints_tier3() -> None:
    state = _ledger(open_bootstrap=True)

    meta = apply_tx(state, _env())

    assert meta["applied"] == "POH_BOOTSTRAP_TIER3_GRANT"
    assert state["accounts"]["alice"]["poh_tier"] == 3
    assert state["accounts"]["alice"]["nonce"] == 1


def test_apply_open_bootstrap_remains_self_only_under_onchain_flag() -> None:
    state = _ledger(open_bootstrap=True)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _env(signer="mallory"))

    assert excinfo.value.reason == "bootstrap_self_only"
