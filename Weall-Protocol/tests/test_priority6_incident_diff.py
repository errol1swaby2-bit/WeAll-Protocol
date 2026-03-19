from __future__ import annotations

from weall.runtime.operator_incident_diff import diff_operator_incident_reports


def test_operator_incident_diff_detects_chain_divergence() -> None:
    left = {
        "summary": {"severity": "ok"},
        "snapshot": {"height": 10, "tip_hash": "aaa"},
        "validator_set": {"validator_set_hash": "set-a", "epoch": 3},
        "startup_fingerprint": {"chain_id": "weall", "node_id": "@n1"},
        "bootstrap_report": {"issues": []},
        "remote_forensics": {"stalled": False},
    }
    right = {
        "summary": {"severity": "critical"},
        "snapshot": {"height": 11, "tip_hash": "bbb"},
        "validator_set": {"validator_set_hash": "set-b", "epoch": 4},
        "startup_fingerprint": {"chain_id": "weall", "node_id": "@n1"},
        "bootstrap_report": {"issues": ["manifest_hash_mismatch"]},
        "remote_forensics": {"stalled": True},
    }

    diff = diff_operator_incident_reports(left, right)

    assert diff["ok"] is False
    assert diff["divergence"]["tip_mismatch"] is True
    assert diff["divergence"]["height_mismatch"] is True
    assert diff["divergence"]["validator_set_mismatch"] is True
    assert "severity_changed" in diff["concerns"]
    assert "bootstrap_issues_changed" in diff["concerns"]
    assert diff["changed_snapshot"]["height"]["left"] == 10
    assert diff["changed_snapshot"]["height"]["right"] == 11


def test_operator_incident_diff_is_ok_for_matching_reports() -> None:
    report = {
        "summary": {"severity": "ok", "bootstrap_ok": True},
        "snapshot": {"height": 5, "tip_hash": "same"},
        "validator_set": {"validator_set_hash": "set-same", "epoch": 2},
        "startup_fingerprint": {"chain_id": "weall", "node_id": "@n1"},
        "bootstrap_report": {"issues": []},
        "remote_forensics": {"stalled": False},
    }

    diff = diff_operator_incident_reports(report, report)

    assert diff["ok"] is True
    assert diff["concerns"] == []
    assert diff["changed_snapshot"] == {}
    assert diff["changed_summary"] == {}
    assert diff["changed_validator_set"] == {}
