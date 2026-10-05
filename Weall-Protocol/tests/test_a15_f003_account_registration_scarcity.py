from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.account_registration_work import (
    ACCOUNT_REGISTRATION_WORK_VERSION,
    account_registration_work_digest,
    account_registration_work_policy,
    leading_zero_bits,
    verify_account_registration_work,
)
from weall.runtime.tx_admission_types import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def _env(*, signer: str = "@alice", nonce: int = 1, pubkey: str = "pk-a") -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "chain_id": "weall-prod",
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "sig_profile": "pq-mldsa-v1",
            "payload": {
                "pubkey": pubkey,
                "recovery_pubkey": "recovery-a",
                "recovery_sig_profile": "pq-mldsa-v1",
                "evidence_kem_pubkey": "kem-a",
                "evidence_kem_algorithm": "ml-kem-768",
            },
            "parent": None,
        }
    )


def _state(bits: int = 8) -> dict:
    return {
        "chain_id": "weall-prod",
        "accounts": {},
        "params": {
            "account_registration_work_required": True,
            "account_registration_work_difficulty_bits": bits,
        },
    }


def _solve(env: TxEnvelope, bits: int) -> int:
    for nonce in range(1_000_000):
        if leading_zero_bits(account_registration_work_digest(env, nonce)) >= bits:
            return nonce
    raise AssertionError("test work solution not found")


def _with_work(env: TxEnvelope, bits: int = 8) -> TxEnvelope:
    nonce = _solve(env, bits)
    raw = env.to_json()
    raw["payload"] = dict(raw["payload"])
    raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
    raw["payload"]["registration_work_nonce"] = nonce
    return TxEnvelope.from_json(raw)


def test_historical_policy_absent_remains_replay_compatible() -> None:
    policy = account_registration_work_policy({"params": {}})
    assert policy.valid is True
    assert policy.required is False
    ok, reason, _ = verify_account_registration_work({"params": {}}, _env())
    assert ok is True
    assert reason == ""


@pytest.mark.parametrize(
    "params,reason",
    [
        ({"account_registration_work_required": True}, "registration_work_difficulty_invalid"),
        (
            {
                "account_registration_work_required": True,
                "account_registration_work_difficulty_bits": 0,
            },
            "registration_work_difficulty_out_of_range",
        ),
        (
            {
                "account_registration_work_required": "maybe",
                "account_registration_work_difficulty_bits": 8,
            },
            "registration_work_required_policy_invalid",
        ),
    ],
)
def test_required_policy_fails_closed_when_invalid(params: dict, reason: str) -> None:
    policy = account_registration_work_policy({"params": params})
    assert policy.valid is False
    ok, got, _ = verify_account_registration_work({"params": params}, _env())
    assert ok is False
    assert got == reason


def test_valid_work_is_bound_to_full_registration_identity() -> None:
    env = _with_work(_env(), 8)
    ok, reason, meta = verify_account_registration_work(_state(8), env)
    assert ok is True
    assert reason == ""
    assert meta["difficulty_bits"] == 8

    variants = [
        _env(signer="@mallory"),
        _env(nonce=2),
        _env(pubkey="pk-b"),
    ]
    work_nonce = env.payload["registration_work_nonce"]
    for variant in variants:
        raw = variant.to_json()
        raw["payload"] = dict(raw["payload"])
        raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
        raw["payload"]["registration_work_nonce"] = work_nonce
        ok2, reason2, _ = verify_account_registration_work(_state(8), TxEnvelope.from_json(raw))
        assert ok2 is False
        assert reason2 == "registration_work_insufficient"


def test_many_signers_cannot_reuse_one_accounts_work() -> None:
    original = _with_work(_env(signer="@acct000"), 8)
    work_nonce = original.payload["registration_work_nonce"]
    accepted = 0
    for index in range(64):
        env = _env(signer=f"@acct{index:03d}")
        raw = env.to_json()
        raw["payload"] = dict(raw["payload"])
        raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
        raw["payload"]["registration_work_nonce"] = work_nonce
        ok, _, _ = verify_account_registration_work(_state(8), TxEnvelope.from_json(raw))
        accepted += int(ok)
    assert accepted == 1


def test_checked_in_production_and_testnet_genesis_require_nonzero_work() -> None:
    for relative in ("configs/genesis.ledger.prod.json", "configs/genesis.ledger.testnet-v1.json"):
        state = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        params = state["params"]
        assert params["account_registration_work_required"] is True
        assert int(params["account_registration_work_difficulty_bits"]) >= 1
        policy = account_registration_work_policy(state)
        assert policy.valid is True
        assert policy.required is True


def test_registration_work_schema_is_signed_payload_surface() -> None:
    from weall.runtime.tx_schema import validate_tx_envelope

    env = _with_work(_env(), 8)
    # Replace cryptographic strings with schema-valid opaque values; this test is
    # about strict payload acceptance, while key decoding is apply-time policy.
    validate_tx_envelope(env.to_json())
