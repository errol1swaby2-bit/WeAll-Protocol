from __future__ import annotations

import copy

import pytest

from weall.crypto.pq_mldsa import generate_mldsa65_keypair, mldsa_backend_status
from weall.crypto.sig import sign_tx_envelope_dict
from weall.ledger.state import LedgerView
from weall.runtime.account_recovery_policy import RECOVERY_RESTRICTION_BLOCKS
from weall.runtime.account_recovery_scheduler import schedule_account_recovery_system_txs
from weall.runtime.domain_apply import ApplyError, apply_tx_atomic
from weall.runtime.poh.state import (
    POH_STATUS_ACTIVE,
    POH_STATUS_EXPIRED,
    TIER2_REMINDER_OFFSETS,
    TIER2_VALIDITY_BLOCKS,
    effective_poh_tier,
    process_tier2_lifecycle,
    set_account_poh_status,
    tier2_lifecycle_fields,
)
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_contracts import load_default_tx_index


def _state(*, guardian_admission: bool | None = None, height: int = 100) -> dict:
    params: dict = {"require_signatures": True}
    if guardian_admission is not None:
        params["guardian_recovery_new_admission"] = guardian_admission
    return {
        "chain_id": "weall-m2-test",
        "network_id": "weall-m2-test",
        "height": height,
        "time": 0,
        "accounts": {},
        "roles": {},
        "params": params,
        "poh": {},
        "last_block_ts_ms": 0,
    }


def _apply(state: dict, tx: dict) -> dict:
    return apply_tx_atomic(copy.deepcopy(state), tx)


def _register(state: dict, account: str, pubkey: str) -> dict:
    return _apply(
        state,
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": account,
            "nonce": 1,
            "payload": {"pubkey": pubkey, "sig_profile": "pq-mldsa-v1"},
            "sig_profile": "pq-mldsa-v1",
            "chain_id": state["chain_id"],
            "sig": "test-direct-apply",
        },
    )


def test_offline_recovery_signature_is_purpose_limited_to_recovery_request() -> None:
    if mldsa_backend_status().get("available") is not True:
        pytest.skip("ML-DSA backend unavailable in this environment")
    main = generate_mldsa65_keypair()
    recovery = generate_mldsa65_keypair()
    replacement = generate_mldsa65_keypair()
    replacement_recovery = generate_mldsa65_keypair()

    state = _register(_state(guardian_admission=False), "@alice", main["pubkey"])
    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_RECOVERY_CONFIG_SET",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "recovery_pubkey": recovery["pubkey"],
                "recovery_sig_profile": "pq-mldsa-v1",
                "recovery_key_commitment": "sha256:" + "1" * 64,
            },
            "sig_profile": "pq-mldsa-v1",
            "chain_id": state["chain_id"],
            "sig": "test-direct-apply",
        },
    )

    recovery_tx = {
        "tx_type": "ACCOUNT_RECOVERY_REQUEST",
        "signer": "@alice",
        "nonce": 3,
        "chain_id": state["chain_id"],
        "network_id": state["network_id"],
        "sig_profile": "pq-mldsa-v1",
        "payload": {
            "request_id": "recovery-1",
            "target": "@alice",
            "method": "offline_key",
            "recovery_generation": 1,
            "new_pubkey": replacement["pubkey"],
            "new_sig_profile": "pq-mldsa-v1",
            "new_recovery_pubkey": replacement_recovery["pubkey"],
            "new_recovery_sig_profile": "pq-mldsa-v1",
        },
    }
    signed_recovery = sign_tx_envelope_dict(tx=recovery_tx, privkey=recovery["privkey"])
    assert verify_tx_signature(state, signed_recovery) is True

    signed_by_main = sign_tx_envelope_dict(tx=recovery_tx, privkey=main["privkey"])
    assert verify_tx_signature(state, signed_by_main) is False

    ordinary_tx = {
        "tx_type": "ACCOUNT_SECURITY_POLICY_SET",
        "signer": "@alice",
        "nonce": 3,
        "chain_id": state["chain_id"],
        "network_id": state["network_id"],
        "sig_profile": "pq-mldsa-v1",
        "payload": {"session_ttl_s": 300},
    }
    ordinary_signed_by_recovery = sign_tx_envelope_dict(tx=ordinary_tx, privkey=recovery["privkey"])
    assert verify_tx_signature(state, ordinary_signed_by_recovery) is False


def test_offline_recovery_atomically_replaces_authority_devices_and_sessions() -> None:
    main = {"pubkey": "main-key"}
    recovery = {"pubkey": "offline-recovery-key"}
    replacement = {"pubkey": "replacement-key"}
    replacement_recovery = {"pubkey": "replacement-recovery-key"}

    state = _register(_state(guardian_admission=False), "@alice", main["pubkey"])
    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_RECOVERY_CONFIG_SET",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "recovery_pubkey": recovery["pubkey"],
                "recovery_sig_profile": "pq-mldsa-v1",
            },
            "sig": "x",
        },
    )
    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@alice",
            "nonce": 3,
            "payload": {"device_id": "phone", "pubkey": "device-key"},
            "sig": "x",
        },
    )
    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_SESSION_KEY_ISSUE",
            "signer": "@alice",
            "nonce": 4,
            "payload": {"session_key": "session-secret", "ttl_s": 600},
            "sig": "x",
        },
    )
    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_RECOVERY_REQUEST",
            "signer": "@alice",
            "nonce": 5,
            "payload": {
                "request_id": "recovery-atomic",
                "target": "@alice",
                "method": "offline_key",
                "recovery_generation": 1,
                "new_pubkey": replacement["pubkey"],
                "new_sig_profile": "pq-mldsa-v1",
                "new_recovery_pubkey": replacement_recovery["pubkey"],
                "new_recovery_sig_profile": "pq-mldsa-v1",
            },
            "sig": "x",
        },
    )
    assert state["accounts"]["@alice"]["locked"] is True
    assert (
        state["accounts"]["@alice"]["recovery"]["requests"]["recovery-atomic"]["status"]
        == "approved"
    )

    queued = schedule_account_recovery_system_txs(state, next_height=101)
    assert queued == 1
    assert any(
        item.get("tx_type") == "ACCOUNT_RECOVERY_FINALIZE" for item in state.get("system_queue", [])
    )

    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_RECOVERY_FINALIZE",
            "signer": "SYSTEM",
            "system": True,
            "nonce": 0,
            "parent": "ACCOUNT_RECOVERY_APPROVE",
            "payload": {"request_id": "recovery-atomic"},
            "sig": "",
        },
    )

    account = state["accounts"]["@alice"]
    assert account["active_keys"] == [replacement["pubkey"]]
    assert account["pubkeys"] == [replacement["pubkey"]]
    assert account["pubkey"] == replacement["pubkey"]
    assert account["locked"] is False
    assert all(
        record.get("revoked") is True
        for record in account["keys"]["by_id"].values()
        if record.get("pubkey") != replacement["pubkey"]
        and record.get("pubkeys", {}).get("mldsa") != replacement["pubkey"]
    )
    assert account["devices"]["by_id"]["phone"]["revoked"] is True
    assert all(record.get("active") is False for record in account["session_keys"].values())
    recovery_state = account["recovery"]
    assert recovery_state["authority_generation"] == 2
    assert recovery_state["offline_key"]["pubkey"] == replacement_recovery["pubkey"]
    assert (
        recovery_state["restriction_until_height"] == state["height"] + RECOVERY_RESTRICTION_BLOCKS
    )

    with pytest.raises(ApplyError) as blocked:
        _apply(
            state,
            {
                "tx_type": "CONTENT_POST_CREATE",
                "signer": "@alice",
                "nonce": 6,
                "payload": {},
                "sig": "x",
            },
        )
    assert blocked.value.reason == "account_recovery_restriction_active"

    # Security maintenance remains available during the restriction.
    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_SECURITY_POLICY_SET",
            "signer": "@alice",
            "nonce": 6,
            "payload": {"session_ttl_s": 120},
            "sig": "x",
        },
    )
    assert state["accounts"]["@alice"]["security_policy"]["session_ttl_s"] == 120


def test_v2_genesis_policy_retires_new_guardian_admission_but_allows_offline_key() -> None:
    main = {"pubkey": "main-key"}
    recovery = {"pubkey": "offline-recovery-key"}
    state = _register(_state(guardian_admission=False), "@alice", main["pubkey"])

    with pytest.raises(ApplyError) as retired:
        _apply(
            state,
            {
                "tx_type": "ACCOUNT_RECOVERY_CONFIG_SET",
                "signer": "@alice",
                "nonce": 2,
                "payload": {"guardians": ["@g1"], "threshold": 1},
                "sig": "x",
            },
        )
    assert retired.value.reason == "guardian_recovery_retired"

    state = _apply(
        state,
        {
            "tx_type": "ACCOUNT_RECOVERY_CONFIG_SET",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "recovery_pubkey": recovery["pubkey"],
                "recovery_sig_profile": "pq-mldsa-v1",
            },
            "sig": "x",
        },
    )
    assert state["accounts"]["@alice"]["recovery"]["mode"] == "offline_key"


def test_tier2_lifecycle_reminders_reverification_and_expiry_fall_back_to_tier1() -> None:
    state = _state(height=0)
    state["accounts"]["@alice"] = {"poh_tier": 2, "poh_status": POH_STATUS_ACTIVE}
    verified = 10
    fields = tier2_lifecycle_fields(verified)
    set_account_poh_status(
        state,
        account_id="@alice",
        poh_tier=2,
        status=POH_STATUS_ACTIVE,
        verified_at_height=verified,
        expires_at_height=fields["expires_at_height"],
        last_updated_height=verified,
    )

    first_reminder = fields["expires_at_height"] - TIER2_REMINDER_OFFSETS[0]
    out = process_tier2_lifecycle(state, next_height=first_reminder)
    assert out == {"reminders": 1, "reverification_opened": 1, "expired": 0, "safe_withdrawals": 0}
    # Idempotent if leader/replay scheduler phases call it again at the same height.
    assert process_tier2_lifecycle(state, next_height=first_reminder) == {
        "reminders": 0,
        "reverification_opened": 0,
        "expired": 0,
        "safe_withdrawals": 0,
    }

    expires = verified + TIER2_VALIDITY_BLOCKS
    assert effective_poh_tier(state, "@alice", at_height=expires) == 2
    assert effective_poh_tier(state, "@alice", at_height=expires + 1) == 1

    out = process_tier2_lifecycle(state, next_height=expires + 1)
    assert out["expired"] == 1
    assert state["poh"]["account_status"]["@alice"]["status"] == POH_STATUS_EXPIRED
    assert state["accounts"]["@alice"]["poh_tier"] == 1
    assert effective_poh_tier(state, "@alice", at_height=expires + 1) == 1
    assert any(
        receipt.get("receipt_type") == "poh_tier2_expired_to_tier1"
        for receipt in state["poh"]["tier2_lifecycle"]["receipts"]
    )


def test_locked_account_cannot_cancel_or_submit_ordinary_actions(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    ledger = LedgerView(
        accounts={
            "@alice": {
                "nonce": 5,
                "poh_tier": 2,
                "banned": False,
                "locked": True,
                "reputation": 10,
            }
        },
        roles={},
    )
    canon = load_default_tx_index()

    cancel = admit_tx(
        {
            "tx_type": "ACCOUNT_RECOVERY_CANCEL",
            "signer": "@alice",
            "nonce": 6,
            "payload": {"request_id": "recovery-1"},
            "sig": "dev",
            "chain_id": "weall-m2-test",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert cancel.ok is False
    assert cancel.reason == "locked"

    ordinary = admit_tx(
        {
            "tx_type": "ACCOUNT_SECURITY_POLICY_SET",
            "signer": "@alice",
            "nonce": 6,
            "payload": {"session_ttl_s": 120},
            "sig": "dev",
            "chain_id": "weall-m2-test",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert ordinary.ok is False
    assert ordinary.reason == "locked"

    reviewer_vote = admit_tx(
        {
            "tx_type": "ACCOUNT_RECOVERY_APPROVE",
            "signer": "@alice",
            "nonce": 6,
            "payload": {"request_id": "recovery-1", "decision": "approve"},
            "sig": "dev",
            "chain_id": "weall-m2-test",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert reviewer_vote.ok is False
    assert reviewer_vote.reason == "locked"

    evidence_bind = admit_tx(
        {
            "tx_type": "ACCOUNT_RECOVERY_APPROVE",
            "signer": "@alice",
            "nonce": 6,
            "payload": {
                "request_id": "recovery-1",
                "decision": "evidence_bind",
                "evidence_id": "evidence-1",
                "key_envelope_commitments": {
                    "@alice": {"envelope_commitment": "sha256:" + "1" * 64}
                },
            },
            "sig": "dev",
            "chain_id": "weall-m2-test",
        },
        ledger,
        canon,
        context="mempool",
    )
    assert evidence_bind.ok is True
