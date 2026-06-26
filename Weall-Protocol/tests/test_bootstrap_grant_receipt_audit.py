from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.executor import WeAllExecutor
from weall.runtime.tx_admission_types import TxEnvelope


def _bootstrap_state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "alice": {
                "nonce": 0,
                "pubkey": "alice-pk",
                "pubkeys": ["alice-pk"],
                "poh_tier": 0,
            }
        },
        "params": {
            "system_signer": "SYSTEM",
            "poh_bootstrap_open": True,
            "poh_bootstrap_max_height": 50,
        },
        "poh": {},
        "roles": {"validators": {"active_set": []}},
    }


def test_bootstrap_tier2_grant_writes_receipt_backed_audit_record() -> None:
    state = _bootstrap_state()
    tx = TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer="alice",
        nonce=1,
        system=False,
        payload={"account_id": "alice", "pubkey": "alice-pk", "reason_code": "founder_live_bootstrap"},
    ).to_json()

    apply_tx(state, tx)

    acct = state["accounts"]["alice"]
    assert acct["poh_tier"] == 2
    assert acct["poh_bootstrap_grant_id"].startswith("poh_bootstrap_grant:")
    assert acct["poh_bootstrap_receipt_id"].startswith("poh_bootstrap_receipt:")

    root = state["poh"]["bootstrap_grants"]
    grant = root["by_id"][acct["poh_bootstrap_grant_id"]]
    assert grant["account_id"] == "alice"
    assert grant["grant_type"] == "poh_tier2_live_verified"
    assert grant["reason_code"] == "founder_live_bootstrap"
    assert grant["authority_path"] == "self_signed_open_bootstrap"
    assert grant["expires_height"] == 50
    assert grant["auditable"] is True
    assert grant["transitional"] is True
    assert grant["receipt_id"] == acct["poh_bootstrap_receipt_id"]
    assert root["by_account"]["alice"] == [grant["grant_id"]]


def test_genesis_bootstrap_direct_seed_writes_audit_record(tmp_path: Path, monkeypatch) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_GENESIS_MODE", "1")
    monkeypatch.setenv("WEALL_NODE_ID", "founder")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "founder")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "f" * 64)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "a" * 64)
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.setenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", "0")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="founder",
        chain_id="weall-test",
        tx_index_path=str(tx_index),
    )

    acct = ex.state["accounts"]["founder"]
    grant_id = acct["poh_bootstrap_grant_id"]
    grant = ex.state["poh"]["bootstrap_grants"]["by_id"][grant_id]
    assert grant["source"] == "genesis_state"
    assert grant["authority_path"] == "genesis_bootstrap_profile"
    assert grant["reason_code"] == "genesis_bootstrap_live"
    assert grant["receipt_id"] == acct["poh_bootstrap_receipt_id"]
