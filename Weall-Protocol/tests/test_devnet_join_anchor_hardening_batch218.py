from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "devnet_join_anchor.py"


def _script(rel: str) -> Path:
    return REPO_ROOT / rel


def _load_helper():
    spec = importlib.util.spec_from_file_location("devnet_join_anchor", HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _genesis() -> dict:
    return {
        "ok": True,
        "chain_id": "weall-controlled-devnet",
        "schema_version": "1",
        "tx_index_hash": "tx-hash",
        "production_consensus_profile_hash": "prod-profile",
        "protocol_profile_hash": "runtime-profile",
        "genesis_bootstrap": {
            "enabled": True,
            "mode": "explicit_genesis_bootstrap",
            "profile_hash": "genesis-profile",
        },
        "trusted_anchor": {
            "height": 0,
            "tip_hash": "genesis-tip",
            "state_root": "genesis-root",
            "finalized_height": 0,
            "finalized_block_id": "",
            "snapshot_hash": "snap-0",
        },
    }


def _identity(height: int = 3) -> dict:
    return {
        "ok": True,
        "height": height,
        "tip_hash": f"tip-{height}",
        "state_root": f"root-{height}",
        "snapshot_anchor": {
            "height": height,
            "tip_hash": f"tip-{height}",
            "state_root": f"root-{height}",
            "finalized_height": max(0, height - 1),
            "finalized_block_id": f"b{max(0, height - 1)}",
            "snapshot_hash": f"snap-{height}",
        },
    }


def test_devnet_join_anchor_scripts_are_syntax_valid_batch218() -> None:
    scripts = [
        "scripts/devnet_export_join_anchor.sh",
        "scripts/devnet_verify_join_anchor.sh",
        "scripts/devnet_wrong_chain_join_reject.sh",
        "scripts/devnet_wrong_genesis_join_reject.sh",
        "scripts/devnet_sync_from_peer.sh",
        "scripts/devnet_boot_joining_node.sh",
    ]
    for rel in scripts:
        proc = subprocess.run(
            ["bash", "-n", str(_script(rel))],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


def test_devnet_join_anchor_cli_commands_are_exposed_batch218() -> None:
    for command in ["export", "verify", "tamper"]:
        proc = subprocess.run(
            [sys.executable, str(HELPER_PATH), command, "--help"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert command in proc.stdout


def test_join_anchor_stable_verification_allows_height_to_advance_batch218() -> None:
    helper = _load_helper()
    expected = helper._expected_from(_genesis(), _identity(height=3))
    actual = helper._expected_from(_genesis(), _identity(height=5))

    assert helper._compare_stable(expected, actual) == []
    assert helper._compare_anchor(expected, actual) != []


def test_join_anchor_rejects_wrong_chain_and_wrong_genesis_profile_batch218() -> None:
    helper = _load_helper()
    expected = helper._expected_from(_genesis(), _identity())

    wrong_chain_genesis = {**_genesis(), "chain_id": "wrong-chain"}
    wrong_chain = helper._expected_from(wrong_chain_genesis, _identity())
    chain_mismatches = helper._compare_stable(expected, wrong_chain)
    assert {m["field"] for m in chain_mismatches} == {"chain_id"}

    wrong_profile_genesis = _genesis()
    wrong_profile_genesis["genesis_bootstrap"] = {
        **wrong_profile_genesis["genesis_bootstrap"],
        "profile_hash": "wrong-profile",
    }
    wrong_profile = helper._expected_from(wrong_profile_genesis, _identity())
    profile_mismatches = helper._compare_stable(expected, wrong_profile)
    assert {m["field"] for m in profile_mismatches} == {"genesis_bootstrap.profile_hash"}


def test_join_anchor_tamper_command_updates_expected_field_batch218(tmp_path: Path) -> None:
    helper = _load_helper()
    anchor = {
        "ok": True,
        "format": helper.FORMAT,
        "expected": helper._expected_from(_genesis(), _identity()),
    }
    src = tmp_path / "anchor.json"
    out = tmp_path / "tampered.json"
    src.write_text(json.dumps(anchor), encoding="utf-8")

    helper.tamper_anchor(str(src), str(out), "genesis_bootstrap.profile_hash", "evil")

    tampered = json.loads(out.read_text(encoding="utf-8"))
    assert tampered["expected"]["genesis_bootstrap"]["profile_hash"] == "evil"


def test_sync_and_join_scripts_can_require_pinned_anchor_batch218() -> None:
    sync = _script("scripts/devnet_sync_from_peer.sh").read_text(encoding="utf-8")
    joining = _script("scripts/devnet_boot_joining_node.sh").read_text(encoding="utf-8")
    for text in [sync, joining]:
        assert "WEALL_JOIN_ANCHOR_PATH" in text
        assert "WEALL_DEVNET_REQUIRE_JOIN_ANCHOR" in text
        assert "devnet_verify_join_anchor.sh" in text
        assert "pinned join anchor" in text


def test_wrong_join_rejection_scripts_are_non_mutating_batch218() -> None:
    combined = "\n".join(
        _script(rel).read_text(encoding="utf-8")
        for rel in [
            "scripts/devnet_wrong_chain_join_reject.sh",
            "scripts/devnet_wrong_genesis_join_reject.sh",
        ]
    )
    assert "/v1/tx/submit" not in combined
    assert "/v1/sync/apply" not in combined
    assert "/v1/dev/demo-seed" not in combined
    assert "join_anchor.py verify" in combined
    assert "join_anchor.py tamper" in combined
