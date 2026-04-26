from __future__ import annotations

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "pubkey": "alice-pk",
                "pubkeys": ["alice-pk"],
                "poh_tier": 0,
            },
            "@genesis": {
                "nonce": 0,
                "pubkey": "genesis-pk",
                "pubkeys": ["genesis-pk"],
                "poh_tier": 3,
            },
        },
        "params": {
            "system_signer": "SYSTEM",
            "poh_bootstrap_open": True,
            "poh_bootstrap_mode": "open",
            "poh_bootstrap_max_height": 50,
            "bootstrap_founder_account": "@genesis",
            "bootstrap_allowlist": {
                "@genesis": {"pubkey": "genesis-pk", "source": "genesis_bootstrap"}
            },
        },
        "poh": {},
        "roles": {},
    }


def _bootstrap_tx(
    *,
    signer: str = "@alice",
    account_id: str = "@alice",
    system: bool = False,
) -> dict:
    return TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer=signer,
        nonce=1,
        system=system,
        payload={"account_id": account_id},
    ).to_json()


def _canon() -> TxIndex:
    return TxIndex.from_raw(
        {
            "tx": {
                "POH_BOOTSTRAP_TIER3_GRANT": {
                    "origin": "SYSTEM",
                    "system_only": True,
                    "subject_gate": "Validator",
                    "context": "block",
                    "receipt_only": False,
                }
            }
        }
    )


def test_genesis_bootstrap_allowlist_metadata_does_not_disable_open_bootstrap_apply_batch232() -> None:
    state = _state()

    apply_tx(state, _bootstrap_tx())

    acct = state["accounts"]["@alice"]
    assert acct["poh_tier"] == 3
    assert acct["poh_bootstrap_mode"] == "open"
    assert acct["poh_bootstrap_granted"] is True


def test_genesis_bootstrap_allowlist_metadata_does_not_disable_open_bootstrap_admission_batch232() -> None:
    state = _state()

    verdict = admit_tx(
        _bootstrap_tx(),
        LedgerView.from_ledger(state),
        canon=_canon(),
        context="mempool",
    )

    assert verdict.ok is True


def test_non_genesis_allowlist_still_conflicts_with_explicit_open_mode_batch232() -> None:
    state = _state()
    state["params"]["bootstrap_allowlist"] = {"@alice": {}}

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _bootstrap_tx(signer="SYSTEM", system=True))

    assert excinfo.value.reason == "bootstrap_mode_conflict"
