from __future__ import annotations

from nacl.signing import SigningKey

from weall.poh.oracle_authority_snapshot import (
    SNAPSHOT_TYPE,
    SNAPSHOT_VERSION,
    sign_authority_snapshot,
    snapshot_hash,
    verify_authority_snapshot_signature,
)


def _snapshot() -> dict:
    return {
        "ok": True,
        "version": SNAPSHOT_VERSION,
        "type": SNAPSHOT_TYPE,
        "chain_id": "weall-prod",
        "genesis_hash": "a" * 64,
        "height": 7,
        "block_hash": "b" * 64,
        "state_root": "c" * 64,
        "tx_index_hash": "d" * 64,
        "schema_version": "1",
        "validator_epoch": 1,
        "validator_set_hash": "e" * 64,
        "authority_source": "on_chain_signed_snapshot",
        "generated_at_ms": 1000,
        "expires_at_ms": 61000,
        "authorized_accounts": ["@operator"],
        "authorized_pubkeys": [],
        "registry": {
            "@operator": {
                "eligible": True,
                "status": "active",
                "poh_tier": 3,
                "active_node_operator": True,
                "reputation_units": 1,
                "locked": False,
                "banned": False,
                "pubkeys": [],
                "reasons": [
                    "active_node_operator",
                    "tier3_or_higher",
                    "positive_reputation",
                    "account_unlocked",
                    "account_not_banned",
                    "active_account_key",
                ],
            }
        },
    }


def test_authority_snapshot_signature_binds_chain_identity_batch241() -> None:
    key = SigningKey(bytes.fromhex("11" * 32))
    pubkey = key.verify_key.encode().hex()
    signed = sign_authority_snapshot(
        _snapshot(),
        signer="@operator",
        pubkey=pubkey,
        privkey_hex=key.encode().hex(),
    )

    assert signed["snapshot_hash"] == snapshot_hash(signed)
    assert verify_authority_snapshot_signature(signed, trusted_pubkeys={pubkey}) is True

    tampered = dict(signed)
    tampered["chain_id"] = "fake-chain"
    assert verify_authority_snapshot_signature(tampered, trusted_pubkeys={pubkey}) is False

    tampered = dict(signed)
    tampered["genesis_hash"] = "f" * 64
    assert verify_authority_snapshot_signature(tampered, trusted_pubkeys={pubkey}) is False


def test_authority_snapshot_rejects_untrusted_signer_batch241() -> None:
    key = SigningKey(bytes.fromhex("22" * 32))
    signed = sign_authority_snapshot(
        _snapshot(),
        signer="@operator",
        pubkey=key.verify_key.encode().hex(),
        privkey_hex=key.encode().hex(),
    )
    assert verify_authority_snapshot_signature(signed, trusted_pubkeys={"33" * 32}) is False
