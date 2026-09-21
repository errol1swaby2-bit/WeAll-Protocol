from __future__ import annotations

from pathlib import Path

import pytest
from starlette.requests import Request

from weall.api import security
from weall.runtime import testnet_capabilities
from weall.runtime.operator_incident_report import (
    classify_local_severity,
    classify_remote_severity,
)
from weall.runtime.runtime_authority import authority_contract_from_lifecycle


def test_serialized_false_does_not_pass_testnet_artifact_or_readiness_boundaries(
    monkeypatch,
) -> None:
    def fake_load(rel: str) -> dict:
        if rel == "generated/public_beta_blocker_report_v1_5.json":
            return {
                "schema": "weall.v1_5.public_beta_blocker_report",
                "ok": "false",
                "public_beta_ready": "false",
                "mainnet_ready": "true",
                "blocker_catalog_count": 15,
                "blocker_count": 15,
            }
        return {"schema": "example", "ok": "true"}

    monkeypatch.setattr(testnet_capabilities, "_load_artifact", fake_load)
    surface = testnet_capabilities.build_testnet_capability_surface({})
    assert all(item["ok"] is False for item in surface["required_artifacts"].values())
    report = surface["public_beta_blocker_report"]
    assert report["public_beta_ready"] is False
    assert report["mainnet_ready"] is False


def test_operator_incident_external_boolean_fields_fail_closed() -> None:
    assert (
        classify_local_severity(
            bootstrap_report={"issues": [], "release_manifest": {}},
            manifest_report={"compatibility_contract": {"ok": "false"}},
        )
        == "critical"
    )
    assert classify_remote_severity(remote_forensics={"ok": "false"}) == "critical"
    assert (
        classify_remote_severity(
            remote_forensics={
                "ok": True,
                "stalled": "false",
                "pending_fetch_requests_count": 1,
                "recent_rejection_summary": {"count": 0},
            }
        )
        == "ok"
    )


def test_session_active_requires_exact_true(monkeypatch) -> None:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (b"x-weall-account", b"acct"),
                (b"x-weall-session-key", b"key"),
            ],
        }
    )
    state = {"accounts": {"acct": {"session_keys": {"key": {}}}}}
    monkeypatch.setattr(
        security,
        "session_record_for",
        lambda sessions, key: {"active": "false", "ttl_s": 0},
    )
    with pytest.raises(PermissionError, match="session_revoked"):
        security.require_account_session(request, state)


def test_runtime_authority_rejects_truthy_effective_strings() -> None:
    contract = authority_contract_from_lifecycle(
        {
            "helper_enabled_effective": "false",
            "bft_enabled_effective": "true",
            "service_roles_effective": [],
        },
        source="test",
    )
    assert contract["helper_effective"] is False
    assert contract["bft_effective"] is False
    assert contract["validator_effective"] is False


def test_public_validator_preflight_has_no_default_true_compatibility_gate() -> None:
    text = (
        Path(__file__).resolve().parents[1] / "scripts" / "public_validator_preflight.py"
    ).read_text(encoding="utf-8")
    assert 'compatibility_contract.get("ok", True)' not in text
    assert 'bool(local_genesis_bootstrap.get("enabled", False))' not in text
    assert 'bool(manifest_genesis_bootstrap.get("enabled", False))' not in text
