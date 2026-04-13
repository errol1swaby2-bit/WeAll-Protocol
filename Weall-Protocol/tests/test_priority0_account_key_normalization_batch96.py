from __future__ import annotations

from weall.ledger.state import LedgerView
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, *, signer: str = "alice", nonce: int = 1, payload: dict | None = None):
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        system=False,
        payload=payload or {},
    ).to_json()


def test_account_register_syncs_legacy_key_views_batch96() -> None:
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


def test_account_key_add_and_revoke_keep_mirrors_deterministic_batch96() -> None:
    state = {"accounts": {}}
    apply_tx(state, _env("ACCOUNT_REGISTER", signer="alice", nonce=1, payload={"pubkey": "pk-main"}))
    apply_tx(state, _env("ACCOUNT_KEY_ADD", signer="alice", nonce=2, payload={"pubkey": "pk-zed"}))
    acct = state["accounts"]["alice"]
    assert acct["pubkeys"] == ["pk-main", "pk-zed"]
    assert acct["active_keys"] == ["pk-main", "pk-zed"]
    assert acct["pubkey"] == "pk-main"

    apply_tx(state, _env("ACCOUNT_KEY_REVOKE", signer="alice", nonce=3, payload={"pubkey": "pk-main"}))
    acct = state["accounts"]["alice"]
    assert acct["pubkeys"] == ["pk-zed"]
    assert acct["active_keys"] == ["pk-zed"]
    assert acct["pubkey"] == "pk-zed"


def test_poh_allowlist_pubkey_match_accepts_canonical_keys_by_id_only_batch96() -> None:
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
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
        signer="SYSTEM",
        nonce=1,
        system=True,
        payload={"account_id": "alice", "pubkey": "alice-pk"},
    ).to_json()
    apply_tx(state, tx)
    acct = state["accounts"]["alice"]
    assert acct["poh_tier"] == 3
    assert acct["poh_bootstrap_mode"] == "allowlist"


def test_ledger_active_pubkeys_normalizes_all_supported_shapes_batch96() -> None:
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
