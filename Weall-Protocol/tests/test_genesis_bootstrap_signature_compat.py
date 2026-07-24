from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.runtime.sigverify import _extract_active_keys


def _tx_index_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")


def test_genesis_bootstrap_emits_profile_aware_mldsa_key_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    account = "@browser-genesis"
    pubkey = "ab" * 1952
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", account)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_NODE_ID", account)

    ex = WeAllExecutor(
        db_path=str(tmp_path / "genesis-browser.db"),
        node_id=account,
        chain_id="genesis-browser-chain",
        tx_index_path=_tx_index_path(),
    )
    state = ex.read_state()
    records = state["accounts"][account]["keys"]["by_id"]
    assert len(records) == 1
    record = next(iter(records.values()))
    assert record["sig_profile"] == "pq-mldsa-v1"
    assert record["pubkeys"] == {"mldsa": pubkey}
    assert record["pubkey"] == pubkey
    assert record["active"] is True
    assert record["revoked"] is False
    assert _extract_active_keys(state["accounts"][account], sig_profile="pq-mldsa-v1") == [pubkey]


def test_legacy_genesis_key_record_without_profile_maps_only_to_mldsa() -> None:
    pubkey = "cd" * 1952
    account = {
        "keys": {
            "by_id": {
                "k:legacy": {
                    "pubkey": pubkey,
                    "key_type": "main",
                    "revoked": False,
                    "revoked_at": None,
                }
            }
        }
    }
    assert _extract_active_keys(account, sig_profile="pq-mldsa-v1") == [pubkey]
    assert _extract_active_keys(account, sig_profile="legacy-ed25519-v1") == []
