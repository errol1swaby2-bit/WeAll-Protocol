from __future__ import annotations

import base64
import copy
import json

import pytest

from weall.crypto.account_keys import (
    account_key_id_for_pubkey,
    account_key_pubkey,
    mldsa_account_key_record,
)
from weall.crypto.pq_mldsa import (
    canonical_mldsa65_public_key,
    mldsa65_public_key_fingerprint,
)
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.apply.identity import apply_identity
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope
from weall.testing.sigtools import deterministic_mldsa_keypair


def _variants(pubkey_hex: str) -> dict[str, str]:
    raw = bytes.fromhex(pubkey_hex)
    b64 = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
    return {
        "hex": pubkey_hex,
        "hex_upper": pubkey_hex.upper(),
        "base64": b64,
        "base64_unpadded": b64.rstrip("="),
        "urlsafe_base64": urlsafe,
        "urlsafe_base64_unpadded": urlsafe.rstrip("="),
    }


def _account_with_key(pubkey: str, *, key_id: str = "legacy-main") -> dict:
    return {
        "nonce": 1,
        "poh_tier": 0,
        "banned": False,
        "locked": False,
        "keys": {
            "by_id": {
                key_id: {
                    "key_id": key_id,
                    "sig_profile": PQ_MLDSA_V1,
                    "pubkeys": {"mldsa": pubkey},
                    "key_type": "main",
                    "active": True,
                    "revoked": False,
                    "created_height": 0,
                }
            }
        },
        "recovery": {
            "mode": None,
            "config": None,
            "offline_key": None,
            "prior_offline_keys": [],
            "authority_generation": 0,
            "failed_attempt_heights": [],
            "history": [],
            "requests": {},
            "proposals": {},
        },
    }


def _env(tx_type: str, *, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="@alice",
        nonce=nonce,
        system=False,
        payload=payload,
    )


def test_a13_f001_all_supported_encodings_share_one_fingerprint_and_key_id() -> None:
    pubkey_hex, _ = deterministic_mldsa_keypair(label="a13-f001-canonical")
    variants = _variants(pubkey_hex)

    canonical = {canonical_mldsa65_public_key(value, encoding="hex") for value in variants.values()}
    fingerprints = {mldsa65_public_key_fingerprint(value) for value in variants.values()}
    key_ids = {account_key_id_for_pubkey(value) for value in variants.values()}
    records = {
        mldsa_account_key_record(pubkey=value)["pubkeys"]["mldsa"] for value in variants.values()
    }

    assert canonical == {pubkey_hex}
    assert len(fingerprints) == 1
    assert len(key_ids) == 1
    assert records == {pubkey_hex}


def test_a13_f001_duplicate_add_fails_across_textual_encodings_without_mutation() -> None:
    pubkey_hex, _ = deterministic_mldsa_keypair(label="a13-f001-duplicate")
    variants = _variants(pubkey_hex)
    state = {"accounts": {"@alice": _account_with_key(variants["base64"])}}
    before = copy.deepcopy(state)

    with pytest.raises(ApplyError, match="key_exists") as caught:
        apply_identity(
            state,
            _env(
                "ACCOUNT_KEY_ADD",
                nonce=2,
                payload={"pubkey": variants["hex"], "sig_profile": PQ_MLDSA_V1},
            ),
        )

    assert caught.value.reason == "key_exists"
    assert state == before


def test_a13_f001_recovery_independence_rejects_same_raw_key_alias() -> None:
    pubkey_hex, _ = deterministic_mldsa_keypair(label="a13-f001-recovery-independent")
    variants = _variants(pubkey_hex)
    state = {"accounts": {"@alice": _account_with_key(variants["base64"])}}

    with pytest.raises(ApplyError, match="recovery_key_must_be_independent") as caught:
        apply_identity(
            state,
            _env(
                "ACCOUNT_RECOVERY_CONFIG_SET",
                nonce=2,
                payload={
                    "recovery_pubkey": variants["hex_upper"],
                    "recovery_sig_profile": PQ_MLDSA_V1,
                },
            ),
        )

    assert caught.value.reason == "recovery_key_must_be_independent"


def test_a13_f001_recovery_freshness_rejects_historical_alias() -> None:
    main_hex, _ = deterministic_mldsa_keypair(label="a13-f001-main")
    recovery_hex, _ = deterministic_mldsa_keypair(label="a13-f001-recovery-history")
    recovery_variants = _variants(recovery_hex)
    account = _account_with_key(main_hex)
    account["recovery"]["prior_offline_keys"] = [
        {
            "pubkey": recovery_variants["base64"],
            "sig_profile": PQ_MLDSA_V1,
            "key_id": "legacy-recovery-id",
            "generation": 1,
        }
    ]
    state = {"accounts": {"@alice": account}}

    with pytest.raises(ApplyError, match="recovery_key_must_be_fresh") as caught:
        apply_identity(
            state,
            _env(
                "ACCOUNT_RECOVERY_CONFIG_SET",
                nonce=2,
                payload={
                    "recovery_pubkey": recovery_variants["urlsafe_base64_unpadded"],
                    "recovery_sig_profile": PQ_MLDSA_V1,
                },
            ),
        )

    assert caught.value.reason == "recovery_key_must_be_fresh"


def test_a13_f001_targeted_revocation_invalidates_all_historical_aliases() -> None:
    pubkey_hex, _ = deterministic_mldsa_keypair(label="a13-f001-revoke")
    variants = _variants(pubkey_hex)
    account = _account_with_key(variants["base64"], key_id="legacy-a")
    account["keys"]["by_id"]["legacy-b"] = {
        "key_id": "legacy-b",
        "sig_profile": PQ_MLDSA_V1,
        "pubkeys": {"mldsa": variants["hex_upper"]},
        "key_type": "secondary",
        "active": True,
        "revoked": False,
        "created_height": 0,
    }
    state = {"height": 9, "accounts": {"@alice": account}}

    apply_identity(
        state,
        _env("ACCOUNT_KEY_REVOKE", nonce=2, payload={"key_id": "legacy-a"}),
    )

    keys = state["accounts"]["@alice"]["keys"]
    canonical_id = account_key_id_for_pubkey(pubkey_hex)
    assert list(keys["by_id"]) == [canonical_id]
    assert keys["by_id"][canonical_id]["revoked"] is True
    assert keys["by_id"][canonical_id]["active"] is False
    assert keys["aliases"]["legacy-a"] == canonical_id
    assert keys["aliases"]["legacy-b"] == canonical_id
    assert state["accounts"]["@alice"]["active_keys"] == []
    assert state["accounts"]["@alice"]["pubkeys"] == []
    assert state["accounts"]["@alice"]["pubkey"] == ""


def test_a13_f001_alias_migration_is_deterministic_across_restart_state_sync_shape() -> None:
    old_hex, _ = deterministic_mldsa_keypair(label="a13-f001-old")
    new_hex, _ = deterministic_mldsa_keypair(label="a13-f001-new")
    old_variants = _variants(old_hex)
    account = _account_with_key(old_variants["base64"], key_id="legacy-a")
    account["keys"]["by_id"]["legacy-b"] = {
        "key_id": "legacy-b",
        "sig_profile": PQ_MLDSA_V1,
        "pubkeys": {"mldsa": old_variants["urlsafe_base64_unpadded"]},
        "key_type": "secondary",
        "active": True,
        "revoked": False,
        "created_height": 0,
    }
    state = {"accounts": {"@alice": account}}

    apply_identity(
        state,
        _env(
            "ACCOUNT_KEY_ADD",
            nonce=2,
            payload={"pubkey": new_hex, "sig_profile": PQ_MLDSA_V1},
        ),
    )

    migrated = state["accounts"]["@alice"]
    old_id = account_key_id_for_pubkey(old_hex)
    new_id = account_key_id_for_pubkey(new_hex)
    assert sorted(migrated["keys"]["by_id"]) == sorted([old_id, new_id])
    assert migrated["keys"]["aliases"]["legacy-a"] == old_id
    assert migrated["keys"]["aliases"]["legacy-b"] == old_id
    assert account_key_pubkey(migrated["keys"]["by_id"][old_id]) == old_hex
    assert account_key_pubkey(migrated["keys"]["by_id"][new_id]) == new_hex
    assert migrated["active_keys"] == sorted([old_hex, new_hex])

    restarted = json.loads(json.dumps(state, sort_keys=True))
    assert restarted == state
    assert restarted["accounts"]["@alice"]["keys"] == migrated["keys"]
