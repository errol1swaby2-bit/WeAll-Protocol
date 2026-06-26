from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]

SENSITIVE_ROUTE_PREFIXES = (
    "/v1/poh/async",
    "/v1/poh/tier2",
    "/v1/poh/live",
    "/v1/session",
    "/v1/net/relay",
    "/v1/observer/edge",
)


class _FakeExecutor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def _env(tx_type: str, nonce: int, payload: dict[str, Any]) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer="@system", nonce=nonce, payload=payload, sig="", system=True)


def _session_state() -> dict[str, Any]:
    return {
        "height": 10,
        "time": 1_800_000_000,
        "accounts": {
            "@alice": {"session_keys": {"alice-session": {"active": True, "issued_at_ts": 1_800_000_000, "ttl_s": 3600}}},
            "@juror": {"session_keys": {"juror-session": {"active": True, "issued_at_ts": 1_800_000_000, "ttl_s": 3600}}},
            "@mallory": {"session_keys": {"mallory-session": {"active": True, "issued_at_ts": 1_800_000_000, "ttl_s": 3600}}},
        },
        "poh": {
            "async_cases": {
                "case-1": {
                    "account_id": "@alice",
                    "status": "reviewable",
                    "assigned_jurors": ["@juror"],
                    "reviewer_restricted_evidence": {"video_cid": "restricted-cid-do-not-leak"},
                    "reviewable_evidence": {"commitment": "c" * 64},
                }
            },
            "tier2_cases": {
                "tier2-1": {
                    "account_id": "@alice",
                    "status": "open",
                    "jurors": {"@juror": {"accepted": True}},
                    "evidence": {"commitment": "t" * 64},
                }
            },
            "live_cases": {
                "live-1": {
                    "account_id": "@alice",
                    "status": "scheduled",
                    "jurors": {"@juror": {"role": "interacting", "accepted": True}},
                    "room_commitment": "r" * 64,
                }
            },
            "live_sessions": {"session-1": {"case_id": "live-1", "status": "open", "room_commitment": "r" * 64}},
            "live_session_participants": {"session-1": {"@alice": {"status": "assigned"}, "@juror": {"status": "assigned"}}},
        },
    }


def test_sensitive_routes_have_explicit_non_generic_metadata() -> None:
    payload = json.loads((ROOT / "generated/api_contract_map_v1_5.json").read_text(encoding="utf-8"))
    routes = payload["routes"]
    sensitive = [r for r in routes if str(r["path"]).startswith(SENSITIVE_ROUTE_PREFIXES)]
    assert sensitive
    for route in sensitive:
        key = f"{route['method']} {route['path']}"
        assert route["metadata_source"] == "specs/api_contracts/v1_5_route_metadata.json", key
        if any(marker in route["path"] for marker in ("/my-cases", "/juror-cases", "/assigned", "/presence", "/webrtc/signals/diagnostics", "/tx_queue/drain")):
            assert route["auth"] != "public_read_redacted_snapshot", key
            assert "no_store" in route["cache_policy"], key


def test_failure_registry_and_artifact_gate_artifacts_are_present() -> None:
    for rel in [
        "generated/api_contract_map_v1_5.json",
        "generated/state_root_vectors_v1_5.json",
        "generated/tokenomics_simulation_v1_5.json",
        "generated/failure_code_registry_v1_5.json",
        "generated/public_validator_bft_preflight_matrix_v1_5.json",
    ]:
        payload = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        assert isinstance(payload, dict), rel

    registry = json.loads((ROOT / "generated/failure_code_registry_v1_5.json").read_text(encoding="utf-8"))
    assert registry["schema"] == "weall.v1_5.failure_code_registry"
    assert registry["unique_code_count"] >= 20
    assert any(item["code"] == "session_required" for item in registry["codes"])

    gate_text = (ROOT / "scripts/check_v15_public_readiness_artifacts.py").read_text(encoding="utf-8")
    for rel in [
        "generated/state_root_vectors_v1_5.json",
        "generated/tokenomics_simulation_v1_5.json",
        "generated/failure_code_registry_v1_5.json",
        "generated/public_validator_bft_preflight_matrix_v1_5.json",
    ]:
        assert rel in gate_text


def test_require_git_tracked_fails_closed_outside_git_checkout() -> None:
    gate_text = (ROOT / "scripts/check_v15_public_readiness_artifacts.py").read_text(encoding="utf-8")
    assert "cannot verify git tracking because this checkout has no .git directory" in gate_text
    assert "--require-git-tracked" in gate_text


def test_poh_sensitive_case_read_requires_session_and_redacts_unrelated_viewer(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    client = _client(_session_state())

    anonymous = client.get("/v1/poh/async/case/case-1")
    assert anonymous.status_code == 200, anonymous.text
    assert anonymous.json()["case"]["reviewer_restricted_evidence"] == {}
    assert "restricted-cid-do-not-leak" not in str(anonymous.json())

    mallory = client.get(
        "/v1/poh/async/case/case-1",
        headers={"x-weall-account": "@mallory", "x-weall-session-key": "mallory-session"},
    )
    assert mallory.status_code == 200, mallory.text
    body = mallory.json()
    assert body["case"]["reviewer_restricted_evidence"] == {}
    assert "restricted-cid-do-not-leak" not in str(body)

    juror = client.get(
        "/v1/poh/async/case/case-1",
        headers={"x-weall-account": "@juror", "x-weall-session-key": "juror-session"},
    )
    assert juror.status_code == 200, juror.text
    assert juror.json()["case"]["reviewer_restricted_evidence"]["video_cid"] == "restricted-cid-do-not-leak"


def test_scoped_poh_queues_reject_session_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    client = _client(_session_state())
    headers = {"x-weall-account": "@mallory", "x-weall-session-key": "mallory-session"}
    for path in [
        "/v1/poh/live/session/session-1/webrtc/signals",
    ]:
        res = client.get(path, headers=headers)
        assert res.status_code in {403, 405}, path + " " + res.text


def test_protocol_upgrade_activation_record_is_not_software_apply() -> None:
    state: dict[str, Any] = {"height": 12}
    apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_DECLARE",
            1,
            {"upgrade_id": "upgrade-read-model", "version": "v1.5.1", "artifact_url": "https://example.invalid/no-fetch.tar.gz"},
        ),
    )
    out = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_ACTIVATE",
            2,
            {"upgrade_id": "upgrade-read-model", "execute_migration": True, "rollback": True, "restart_node": True},
        ),
    )
    record = out["governance_activation_record"]
    boundary = out["record_only_boundary"]
    assert state["protocol"]["governance_activation_record"] == record
    assert state["protocol"]["active"]["software_applied"] is False
    assert record["software_applied"] is False
    assert record["artifact_fetched"] is False
    assert record["migration_executed"] is False
    assert record["rollback_available"] is False
    assert record["operator_action_required"] is True
    assert record["automatic_upgrade_supported"] is False
    assert boundary["migration_executed"] is False
    assert boundary["rollback_available"] is False
    assert boundary["automatic_upgrade_supported"] is False
    assert set(boundary["requested_execution_fields_ignored"]) == {"execute_migration", "rollback", "restart_node"}


def test_15_generated_artifacts_preserve_truth_boundaries() -> None:
    state_vectors = json.loads((ROOT / "generated/state_root_vectors_v1_5.json").read_text(encoding="utf-8"))
    assert state_vectors["schema"] == "weall.v1_5.state_root_vectors"
    names = {v["name"] for v in state_vectors["vectors"]}
    assert {"poh_async_and_live_commitments", "governance_protocol_record_only", "economics_locked_supply_surface"}.issubset(names)
    assert state_vectors["canonicalization_contract"]["consensus_relevant_policy_must_not_live_under_meta"] is True

    econ = json.loads((ROOT / "generated/tokenomics_simulation_v1_5.json").read_text(encoding="utf-8"))
    assert econ["truth_boundaries"]["live_economics_enabled"] is False
    assert econ["additional_truth_boundaries"]["fee_markets_enabled"] is False
    assert econ["activation_blockade_checklist"]
    assert len(econ["farming_and_capture_scenarios"]) >= 3

    bft = json.loads((ROOT / "generated/public_validator_bft_preflight_matrix_v1_5.json").read_text(encoding="utf-8"))
    assert bft["truth_boundaries"]["public_validator_enabled"] is False
    assert bft["truth_boundaries"]["public_multi_validator_bft_ready"] is False
    assert bft["truth_boundaries"]["artifact_is_readiness_plan_not_proof"] is True
    assert len(bft["required_scenarios"]) >= 6
