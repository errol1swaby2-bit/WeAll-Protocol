from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "devnet_cross_node_convergence.py"


def _script(rel: str) -> Path:
    return REPO_ROOT / rel


def _load_helper():
    spec = importlib.util.spec_from_file_location("devnet_cross_node_convergence", HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_devnet_cross_node_convergence_scripts_are_syntax_valid() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(_script("scripts/devnet_cross_node_convergence.sh"))],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    proc = subprocess.run(
        [sys.executable, "-S", "-m", "py_compile", str(HELPER_PATH)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_cross_node_convergence_cli_exposes_scenarios_and_dry_run() -> None:
    for args in [
        ["--help"],
        ["--list-scenarios"],
        ["--dry-run", "--account", "@dry_run_cross_node"],
    ]:
        proc = subprocess.run(
            [sys.executable, "-S", str(HELPER_PATH), *args],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "node" in proc.stdout.lower()

    dry = subprocess.run(
        [sys.executable, "-S", str(HELPER_PATH), "--dry-run", "--account", "@dry_run_cross_node"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    out = json.loads(dry.stdout)
    assert out["ok"] is True
    assert out["dry_run"] is True
    assert out["account"] == "@dry_run_cross_node"
    assert {step["step"] for step in out["steps"]} >= {
        "create_account",
        "sync",
        "assert_account_visible",
        "submit_profile_update",
        "converge_node2_tx",
        "compare_state_roots",
    }
    assert any(step.get("mode") == "node2_producer_or_edge_relay_to_node1" for step in out["steps"])


def test_cross_node_convergence_scenarios_cover_both_directions() -> None:
    helper = _load_helper()
    scenarios = {scenario["name"]: scenario for scenario in helper.SCENARIOS}
    assert "node1-account-register-visible-node2" in scenarios
    assert "node2-profile-update-visible-node1" in scenarios
    assert "state-root-identity-parity-after-bidirectional-sync" in scenarios
    assert scenarios["node1-account-register-visible-node2"]["direction"] == "node1_to_node2"
    assert scenarios["node2-profile-update-visible-node1"]["direction"] == "node2_to_node1"
    assert scenarios["node1-account-register-visible-node2"]["tx_type"] == "ACCOUNT_REGISTER"
    assert scenarios["node2-profile-update-visible-node1"]["tx_type"] == "PROFILE_UPDATE"


def test_cross_node_convergence_compare_identity_detects_mismatch() -> None:
    helper = _load_helper()
    left = {
        "chain_id": "weall-devnet",
        "height": 4,
        "tip_hash": "tip-a",
        "state_root": "root-a",
        "schema_version": "1",
        "tx_index_hash": "tx-index",
        "protocol_profile_hash": "profile",
    }
    right = dict(left)
    assert helper.compare_identities(left, right) == []

    right["state_root"] = "root-b"
    right["tip_hash"] = "tip-b"
    mismatch_fields = {m["field"] for m in helper.compare_identities(left, right)}
    assert mismatch_fields == {"tip_hash", "state_root"}


def test_cross_node_convergence_rejects_invalid_chain_manifest() -> None:
    helper = _load_helper()
    valid = {
        "chain_manifest": {
            "ok": True,
            "mode": "controlled_devnet",
            "tx_index_hash": "a" * 64,
            "actual_tx_index_hash": "a" * 64,
            "tx_index_hash_matches": True,
            "issues": [],
        }
    }
    assert helper.chain_manifest_failures(valid, node="node1") == []

    invalid = {
        "chain_manifest": {
            "ok": False,
            "mode": "devnet",
            "tx_index_hash": "a" * 64,
            "actual_tx_index_hash": "b" * 64,
            "tx_index_hash_matches": False,
            "issues": ["chain_manifest_mode_mismatch", "chain_manifest_tx_index_hash_mismatch"],
        }
    }
    failures = helper.chain_manifest_failures(invalid, node="node2")
    assert {failure["failure"] for failure in failures} == {
        "chain_manifest_not_ok",
        "chain_manifest_mode_not_controlled_devnet",
        "chain_manifest_tx_index_hash_not_current",
    }


def test_cross_node_convergence_tx_visibility_classifier() -> None:
    helper = _load_helper()
    ok, detail = helper.classify_tx_visibility(status={"status": "confirmed"})
    assert ok is True
    assert detail["ok"] is True

    ok, detail = helper.classify_tx_visibility(status={"status": "pending"})
    assert ok is False
    assert detail["failure"] == "tx_not_visible_with_expected_status"


def test_cross_node_convergence_uses_normal_public_flow_not_demo_seed() -> None:
    combined = "\n".join(
        _script(rel).read_text(encoding="utf-8")
        for rel in [
            "scripts/devnet_cross_node_convergence.py",
            "scripts/devnet_cross_node_convergence.sh",
        ]
    )
    assert "/v1/dev/demo-seed" not in combined
    assert "demo-seed" not in combined
    assert "devnet_tx.py" in combined
    assert "devnet_sync_from_peer.sh" in combined
    assert "devnet_compare_state_roots.sh" in combined
    assert "edge_relay_to_canonical_producer" in combined
    assert "--tx-out" in _script("scripts/devnet_tx.py").read_text(encoding="utf-8")
    assert "/v1/tx/submit" in _script("scripts/devnet_tx.py").read_text(encoding="utf-8")


def test_cross_node_convergence_unreachable_node_returns_json() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-S",
            str(HELPER_PATH),
            "--node1-api",
            "http://127.0.0.1:1",
            "--node2-api",
            "http://127.0.0.1:2",
            "--http-timeout",
            "0.1",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    out = json.loads(proc.stdout)
    assert out["ok"] is False
    assert out["failure"] == "node_api_unreachable"
    assert out["unreachable"]["node"] == "node1"
    assert "devnet_boot_genesis_node.sh" in "\n".join(out["next_steps"])


def test_cross_node_convergence_relay_helper_reports_missing_tx_file(tmp_path: Path) -> None:
    helper = _load_helper()
    out = helper.relay_signed_tx_to_canonical_producer(
        producer_api="http://127.0.0.1:8001",
        tx_path=str(tmp_path / "missing.json"),
        tx_id="tx:missing",
        timeout_s=0.1,
        poll_s=0.01,
        http_timeout=0.1,
    )
    assert out["ok"] is False
    assert out["failure"] == "signed_tx_file_missing"


def test_cross_node_convergence_wait_tx_status_stops_on_invalid(monkeypatch) -> None:
    helper = _load_helper()
    calls = {"n": 0}

    def fake_status(api: str, tx_id: str, *, timeout: float = 15.0, node: str = ""):
        calls["n"] += 1
        return {"ok": True, "status": "invalid", "tx_id": tx_id}

    monkeypatch.setattr(helper, "_tx_status", fake_status)
    out = helper.wait_tx_status("http://node", "tx:1", timeout_s=1, poll_s=0.01, node="node1")
    assert out["status"] == "invalid"
    assert calls["n"] == 1


def test_cross_node_rejected_receipt_comparator_requires_two_real_matching_committed_receipts() -> None:
    helper = _load_helper()
    tx_id = "tx:" + "b" * 64
    valid = {
        "ok": True,
        "tx_id": tx_id,
        "status": "rejected",
        "source": "committed_apply_receipt",
        "local_state_synced": True,
        "apply_ok": False,
        "height": 15,
        "block_id": "block:15",
        "included_ts_ms": 300000,
        "tx_type": "ACCOUNT_SESSION_KEY_REVOKE",
        "signer": "@alice",
        "code": "invalid_tx",
        "reason": "unknown_session_key",
    }
    assert helper.rejected_receipt_mismatches(
        dict(valid), dict(valid), tx_id=tx_id, account="@alice"
    ) == []

    for mutation, required_failure in (
        ({"status": "confirmed"}, "follower_not_rejected"),
        ({"source": "mocked_receipt"}, "follower_not_committed_apply_receipt"),
        ({"apply_ok": True}, "follower_apply_not_false"),
        ({"local_state_synced": False}, "follower_not_locally_synced"),
        ({"height": 0}, "follower_no_committed_height"),
        ({"block_id": ""}, "follower_no_committed_block_id"),
        ({"reason": "rejected_for_other_reason"}, "follower_wrong_reason"),
        ({"signer": "@other"}, "follower_wrong_signer"),
        ({"tx_id": "tx:wrong"}, "follower_tx_id_mismatch"),
    ):
        tampered = {**valid, **mutation}
        failures = helper.rejected_receipt_mismatches(
            valid, tampered, tx_id=tx_id, account="@alice"
        )
        assert required_failure in failures
        assert any(failure.startswith("cross_node_") for failure in failures)

    assert "producer_not_committed_apply_receipt" in helper.rejected_receipt_mismatches(
        {"status": "rejected", "tx_id": tx_id}, valid, tx_id=tx_id, account="@alice"
    )


def test_rejected_receipt_probe_opt_in_dry_run_is_explicit_and_does_not_claim_bft() -> None:
    proc = subprocess.run(
        [
            sys.executable, "-S", str(HELPER_PATH), "--dry-run",
            "--check-rejected-receipt", "--account", "@dry_run_cross_node",
        ],
        cwd=REPO_ROOT, text=True, capture_output=True, timeout=10, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    scenario = next(
        s for s in out["scenarios"]
        if s["name"] == "node1-failed-apply-receipt-visible-node2"
    )
    assert scenario["tx_type"] == "ACCOUNT_SESSION_KEY_REVOKE"
    assert scenario["expect"] == "same_committed_failed_apply_receipt_after_verified_delta_sync"
    assert "QC" in scenario["description"]

    default_proc = subprocess.run(
        [sys.executable, "-S", str(HELPER_PATH), "--dry-run"],
        cwd=REPO_ROOT, text=True, capture_output=True, timeout=10, check=False,
    )
    assert default_proc.returncode == 0
    defaults = json.loads(default_proc.stdout)
    assert not any(
        s["name"] == "node1-failed-apply-receipt-visible-node2"
        for s in defaults["scenarios"]
    )
