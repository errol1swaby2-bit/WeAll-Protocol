from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.node_operator_responsibilities import evaluate_validator_responsibility
from weall.runtime.validator_readiness_runner import (
    ValidatorReadinessError,
    build_validator_readiness_receipt,
    main as validator_readiness_main,
    validate_validator_readiness_payload,
)

ROOT = Path(__file__).resolve().parents[1]


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> dict:
    return {"tx_type": tx_type, "signer": signer, "nonce": nonce, "payload": payload, "system": system, "sig": ""}


def _state() -> dict:
    return {
        "height": 5,
        "accounts": {
            "@op": {
                "poh_tier": 2,
                "reputation_milli": 6000,
                "devices": {"by_id": {"node:1": {"device_type": "node", "pubkey": "node-pub", "revoked": False}}},
            }
        },
        "roles": {"node_operators": {"active_set": ["@op"], "by_id": {"@op": {"account_id": "@op", "active": True, "enrolled": True}}}},
    }


def _receipt(**overrides) -> dict:
    payload = build_validator_readiness_receipt(
        account_id="@op",
        node_pubkey="node-pub",
        bft_pubkey="bft-pub",
        chain_id="weall-prod",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="sha256:manifest",
        tx_index_hash="sha256:tx-index",
        runtime_profile_hash="sha256:runtime-profile",
        readiness_expires_height=50,
    )
    payload.update(overrides)
    return payload


def test_validator_live_readiness_receipt_is_deterministic_and_bound() -> None:
    receipt = _receipt()
    checked = validate_validator_readiness_payload(receipt, account_id="@op", expected_node_pubkey="node-pub", current_height=5)
    assert checked["readiness_receipt_hash"] == receipt["readiness_receipt_hash"]
    assert checked["bft_pubkey"] == "bft-pub"
    assert checked["runtime_profile_hash"] == "sha256:runtime-profile"

    tampered = dict(receipt)
    tampered["tx_index_hash"] = "sha256:other"
    with pytest.raises(ValidatorReadinessError) as exc:
        validate_validator_readiness_payload(tampered, account_id="@op", expected_node_pubkey="node-pub", current_height=5)
    assert "readiness_receipt_hash_mismatch" in str(exc.value)


def test_validator_live_readiness_rejects_failed_required_checks() -> None:
    receipt = _receipt()
    checks = dict(receipt["readiness_checks"])
    checks["bft_signer_ready"] = False
    receipt["readiness_checks"] = checks
    # Recompute hash so this proves failed checks are rejected even when the receipt is self-consistent.
    receipt = build_validator_readiness_receipt(
        account_id="@op",
        node_pubkey="node-pub",
        bft_pubkey="bft-pub",
        chain_id="weall-prod",
        schema_version="1",
        protocol_version="1.25.0",
        manifest_hash="sha256:manifest",
        tx_index_hash="sha256:tx-index",
        runtime_profile_hash="sha256:runtime-profile",
        readiness_expires_height=50,
        readiness_checks=checks,
    )
    with pytest.raises(ValidatorReadinessError) as exc:
        validate_validator_readiness_payload(receipt, account_id="@op", expected_node_pubkey="node-pub", current_height=5)
    assert "readiness_check_failed:bft_signer_ready" in str(exc.value)


def test_validator_readiness_verify_requires_live_receipt() -> None:
    st = _state()
    apply_tx(st, _env("NODE_OPERATOR_VALIDATOR_OPT_IN", "@op", 1, {"account_id": "@op", "node_pubkey": "node-pub"}))

    with pytest.raises(Exception) as exc:
        apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 2, {"account_id": "@op", "verification_status": "verified", "manifest_hash": "sha256:manifest", "tx_index_hash": "sha256:tx-index", "readiness_receipt_hash": "sha256:fake", "readiness_expires_height": 50}, system=True))
    assert "validator_live_readiness_invalid" in str(exc.value)

    receipt = _receipt()
    payload = dict(receipt)
    payload["verification_status"] = "verified"
    result = apply_tx(st, _env("VALIDATOR_READINESS_VERIFY", "SYSTEM", 3, payload, system=True))
    assert result["verified"] is True
    readiness = evaluate_validator_responsibility(st, "@op", node_pubkey="node-pub")
    assert readiness.active is True
    assert readiness.details["readiness_receipt_hash"] == receipt["readiness_receipt_hash"]


def test_validator_readiness_cli_generates_and_verifies_receipt(tmp_path: Path, capsys) -> None:
    rc = validator_readiness_main([
        "generate",
        "--account-id",
        "@op",
        "--node-pubkey",
        "node-pub",
        "--bft-pubkey",
        "bft-pub",
        "--chain-id",
        "weall-prod",
        "--schema-version",
        "1",
        "--protocol-version",
        "1.25.0",
        "--manifest-hash",
        "sha256:manifest",
        "--tx-index-hash",
        "sha256:tx-index",
        "--runtime-profile-hash",
        "sha256:runtime-profile",
        "--readiness-expires-height",
        "50",
    ])
    assert rc == 0
    receipt = json.loads(capsys.readouterr().out)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    rc = validator_readiness_main([
        "verify",
        "--receipt",
        str(receipt_path),
        "--account-id",
        "@op",
        "--node-pubkey",
        "node-pub",
        "--current-height",
        "5",
    ])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
