from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from weall.ledger.state import LedgerView
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_schema import AccountKeyRevokePayload


def _env(tx_type: str, *, signer: str = "alice", nonce: int = 1, payload: dict | None = None):
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        system=False,
        payload=payload or {},
    ).to_json()


def test_account_register_syncs_legacy_key_views() -> None:
    state = {"accounts": {}}
    apply_tx(
        state,
        _env("ACCOUNT_REGISTER", signer="alice", nonce=1, payload={"pubkey": "pk-main"}),
    )
    acct = state["accounts"]["alice"]
    assert acct["pubkey"] == "pk-main"
    assert acct["pubkeys"] == ["pk-main"]
    assert acct["active_keys"] == ["pk-main"]
    assert "keys" in acct and "by_id" in acct["keys"]


def test_account_key_add_and_revoke_keep_mirrors_deterministic() -> None:
    state = {"accounts": {}}
    apply_tx(
        state, _env("ACCOUNT_REGISTER", signer="alice", nonce=1, payload={"pubkey": "pk-main"})
    )
    apply_tx(state, _env("ACCOUNT_KEY_ADD", signer="alice", nonce=2, payload={"pubkey": "pk-zed"}))
    acct = state["accounts"]["alice"]
    assert acct["pubkeys"] == ["pk-main", "pk-zed"]
    assert acct["active_keys"] == ["pk-main", "pk-zed"]
    assert acct["pubkey"] == "pk-main"

    by_id = acct["keys"]["by_id"]
    main_kid = next(
        kid
        for kid, rec in by_id.items()
        if rec.get("pubkeys", {}).get("mldsa") == "pk-main"
    )
    added_kid = next(
        kid
        for kid, rec in by_id.items()
        if rec.get("pubkeys", {}).get("mldsa") == "pk-zed"
    )
    assert by_id[main_kid]["key_id"] == main_kid
    assert by_id[added_kid]["key_id"] == added_kid

    apply_tx(
        state,
        _env("ACCOUNT_KEY_REVOKE", signer="alice", nonce=3, payload={"key_id": main_kid}),
    )
    acct = state["accounts"]["alice"]
    assert acct["pubkeys"] == ["pk-zed"]
    assert acct["active_keys"] == ["pk-zed"]
    assert acct["pubkey"] == "pk-zed"
    assert acct["keys"]["by_id"][main_kid]["active"] is False
    assert acct["keys"]["by_id"][main_kid]["revoked"] is True


def test_account_key_revoke_payload_and_handler_share_key_id_contract() -> None:
    parsed = AccountKeyRevokePayload.model_validate({"key_id": "k:canonical"})
    assert parsed.key_id == "k:canonical"
    with pytest.raises(ValidationError):
        AccountKeyRevokePayload.model_validate({"pubkey": "pk-main"})

    state = {"accounts": {}}
    apply_tx(
        state, _env("ACCOUNT_REGISTER", signer="alice", nonce=1, payload={"pubkey": "pk-main"})
    )
    kid = next(iter(state["accounts"]["alice"]["keys"]["by_id"]))
    apply_tx(
        state,
        _env("ACCOUNT_KEY_REVOKE", signer="alice", nonce=2, payload={"key_id": kid}),
    )
    assert state["accounts"]["alice"]["keys"]["by_id"][kid]["revoked"] is True


def test_account_key_revoke_accepts_canonical_record_id_from_legacy_map_key() -> None:
    state = {"accounts": {}}
    apply_tx(
        state, _env("ACCOUNT_REGISTER", signer="alice", nonce=1, payload={"pubkey": "pk-main"})
    )
    acct = state["accounts"]["alice"]
    by_id = acct["keys"]["by_id"]
    canonical_kid, rec = next(iter(by_id.items()))
    legacy_kid = "k:" + hashlib.sha256(b"pk-main").hexdigest()[:16]
    assert legacy_kid != canonical_kid

    acct["keys"]["by_id"] = {legacy_kid: rec}
    apply_tx(
        state,
        _env(
            "ACCOUNT_KEY_REVOKE",
            signer="alice",
            nonce=2,
            payload={"key_id": canonical_kid},
        ),
    )
    legacy_rec = state["accounts"]["alice"]["keys"]["by_id"][legacy_kid]
    assert legacy_rec["revoked"] is True
    assert legacy_rec["active"] is False


def test_poh_allowlist_pubkey_match_accepts_canonical_keys_by_id_only() -> None:
    state = {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "alice": {
                "nonce": 0,
                "poh_tier": 0,
                "keys": {
                    "by_id": {
                        "k1": {"pubkey": "alice-pk", "revoked": False},
                    }
                },
            }
        },
        "params": {
            "system_signer": "SYSTEM",
            "bootstrap_allowlist": {"alice": {"pubkey": "alice-pk"}},
            "bootstrap_expires_height": 50,
        },
        "poh": {},
        "roles": {},
    }
    tx = TxEnvelope(
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer="SYSTEM",
        nonce=1,
        system=True,
        payload={"account_id": "alice", "pubkey": "alice-pk"},
    ).to_json()
    apply_tx(state, tx)
    acct = state["accounts"]["alice"]
    assert acct["poh_tier"] == 2
    assert acct["poh_bootstrap_mode"] == "allowlist"


def test_ledger_active_pubkeys_normalizes_all_supported_shapes() -> None:
    lv = LedgerView.from_ledger(
        {
            "accounts": {
                "alice": {
                    "pubkey": "legacy-main",
                    "pubkeys": ["legacy-main", "legacy-extra"],
                    "active_keys": ["legacy-main", "legacy-extra"],
                    "keys": {
                        "by_id": {
                            "k1": {"pubkey": "canonical-main", "revoked": False},
                            "k2": {"pubkey": "revoked-key", "revoked": True},
                        }
                    },
                }
            }
        }
    )
    keys = lv.get_active_keys("alice")
    assert keys == ["legacy-main", "legacy-extra", "canonical-main"]
