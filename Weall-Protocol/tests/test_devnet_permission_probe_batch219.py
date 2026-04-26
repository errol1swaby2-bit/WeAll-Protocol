from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

from weall.runtime.tx_schema import TX_PAYLOADS, validate_tx_envelope

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "devnet_permission_probe.py"


def _script(rel: str) -> Path:
    return REPO_ROOT / rel


def _load_helper():
    spec = importlib.util.spec_from_file_location("devnet_permission_probe", HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_devnet_permission_probe_scripts_are_syntax_valid_batch219() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(_script("scripts/devnet_permission_probe.sh"))],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    proc = subprocess.run(
        [sys.executable, "-S", "-m", "py_compile", str(_script("scripts/devnet_permission_probe.py"))],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_devnet_permission_probe_cli_is_exposed_batch219() -> None:
    for args in [["--help"], ["--list-probes"]]:
        proc = subprocess.run(
            [sys.executable, "-S", str(HELPER_PATH), *args],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "probe" in proc.stdout.lower()


def test_permission_probe_covers_core_tier_and_role_gates_batch219() -> None:
    helper = _load_helper()
    by_name = {probe.name: probe for probe in helper.PROBES}

    expected = {
        "tier0-profile-update-allowed": ("PROFILE_UPDATE", "Tier0+", "allow"),
        "tier1-transfer-blocked": ("BALANCE_TRANSFER", "Tier1+", "reject"),
        "tier1-message-blocked": ("DIRECT_MESSAGE_SEND", "Tier1+", "reject"),
        "tier2-group-create-blocked": ("GROUP_CREATE", "Tier2+", "reject"),
        "tier2-reaction-blocked": ("CONTENT_REACTION_SET", "Tier2+", "reject"),
        "tier3-post-create-blocked": ("CONTENT_POST_CREATE", "Tier3+", "reject"),
        "tier3-governance-create-blocked": ("GOV_PROPOSAL_CREATE", "Tier3+", "reject"),
        "juror-tier2-review-blocked": ("POH_TIER2_REVIEW_SUBMIT", "Juror", "reject"),
        "juror-tier3-verdict-blocked": ("POH_TIER3_VERDICT_SUBMIT", "Juror", "reject"),
    }
    assert set(expected).issubset(by_name)
    for name, (tx_type, gate, expected_result) in expected.items():
        probe = by_name[name]
        assert probe.tx_type == tx_type
        assert probe.gate == gate
        assert probe.expected == expected_result


def test_permission_probe_dry_run_builds_valid_payload_plan_batch219() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-S",
            str(HELPER_PATH),
            "--dry-run",
            "--account",
            "@permission_probe_test",
            "--keyfile",
            "/tmp/permission-probe-test.json",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["ok"] is True
    assert out["dry_run"] is True
    assert out["account"] == "@permission_probe_test"
    assert {p["tx_type"] for p in out["probes"]} >= {
        "PROFILE_UPDATE",
        "BALANCE_TRANSFER",
        "GROUP_CREATE",
        "CONTENT_POST_CREATE",
        "GOV_PROPOSAL_CREATE",
        "POH_TIER2_REVIEW_SUBMIT",
        "POH_TIER3_VERDICT_SUBMIT",
    }


def test_permission_probe_uses_normal_public_tx_flow_not_demo_seed_batch219() -> None:
    combined = "\n".join(
        _script(rel).read_text(encoding="utf-8")
        for rel in ["scripts/devnet_permission_probe.py", "scripts/devnet_permission_probe.sh"]
    )
    assert "/v1/dev/demo-seed" not in combined
    assert "demo-seed" not in combined
    assert "devnet_tx.py" in combined
    assert "/v1/tx/submit" in _script("scripts/devnet_tx.py").read_text(encoding="utf-8")


def test_permission_probe_result_classifier_fails_confirmed_blocked_tx_batch219() -> None:
    helper = _load_helper()
    probe = next(p for p in helper.PROBES if p.expected == "reject")

    class Proc:
        returncode = 0
        stdout = json.dumps({"tx_status": {"status": "confirmed"}})
        stderr = ""

    ok, detail = helper.classify_probe_result(probe, Proc())
    assert ok is False
    assert detail["failure"] == "blocked_probe_confirmed"


def test_poh_tier3_request_open_has_strict_payload_schema_batch219() -> None:
    assert "POH_TIER3_REQUEST_OPEN" in TX_PAYLOADS
    validate_tx_envelope(
        {
            "tx_type": "POH_TIER3_REQUEST_OPEN",
            "signer": "alice",
            "nonce": 1,
            "payload": {
                "account_id": "alice",
                "session_commitment": "session:cmt",
                "room_commitment": "room:cmt",
                "prompt_commitment": "prompt:cmt",
                "device_pairing_commitment": "device:cmt",
                "relay_commitment": "relay:cmt",
            },
            "sig": "sig",
            "parent": None,
            "system": False,
            "chain_id": "test",
        }
    )
