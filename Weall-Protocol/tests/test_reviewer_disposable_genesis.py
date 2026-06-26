from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_reviewer_builder_generates_disposable_chain_without_founder_key_dependency(tmp_path: Path) -> None:
    out_dir = tmp_path / "reviewer"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_reviewer_lan_genesis.py"),
            "--out-dir",
            str(out_dir),
            "--force",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    summary = json.loads(result.stdout)
    assert summary["ok"] is True
    assert summary["account"] == "@reviewer-genesis"
    assert summary["chain_id"] == "weall-reviewer-lan"
    assert summary["pubkey"]
    assert "Disposable reviewer rehearsal chain" in summary["truth_boundary"]

    ledger = json.loads(Path(summary["ledger_path"]).read_text(encoding="utf-8"))
    manifest = json.loads(Path(summary["manifest_path"]).read_text(encoding="utf-8"))
    env_text = Path(summary["env_path"]).read_text(encoding="utf-8")

    assert ledger["chain_id"] == "weall-reviewer-lan"
    assert "@reviewer-genesis" in ledger["accounts"]
    assert "@errol-genesis" not in json.dumps(ledger, sort_keys=True)
    assert "c195d59d38ecf84b9baa227aff88960759afb72d2150f6e27a3187d0a3ae08be" not in json.dumps(
        ledger, sort_keys=True
    )

    assert manifest["chain_id"] == "weall-reviewer-lan"
    assert manifest["trusted_authority_pubkeys"] == [summary["pubkey"]]
    assert manifest["genesis_hash"] == summary["genesis_hash"]
    assert manifest["genesis_state_root"] == summary["genesis_state_root"]

    assert "WEALL_NODE_PRIVKEY" in env_text
    assert "WEALL_GENESIS_LEDGER_PATH" in env_text
    assert "WEALL_CHAIN_MANIFEST_PATH" in env_text


def test_reviewer_genesis_wrapper_uses_sanitized_bundle_build_and_height_gate() -> None:
    text = _read("scripts/reviewer_lan_genesis_rehearsal.sh")
    assert "build_reviewer_lan_genesis.py" in text
    assert "Disposable reviewer rehearsal chain" in text
    assert "-u WEALL_NODE_PRIVKEY" in text
    assert "-u WEALL_VALIDATOR_ACCOUNT" in text
    assert "build_external_observer_bundle.py" in text
    assert "verify_node_operator_onboarding_bundle.py" in text
    assert "Waiting for block height to advance" in text
    assert "Genesis height did not advance above 0" in text
    assert "--pull-reviewer-artifacts" in text


def test_reviewer_quickstart_documents_artifact_pull_flow() -> None:
    text = _read("docs/REVIEWER_LAN_REHEARSAL_QUICKSTART.md")
    assert "disposable reviewer Genesis chain" in text
    assert "canonical production Genesis private key" in text
    assert "reviewer-chain-manifest.json" in text
    assert "--pull-reviewer-artifacts" in text
    assert "canonical production Genesis authority" in text
    assert "public multi-validator BFT readiness" in text
    assert "nlnet" not in text.lower()


def test_no_founder_secret_material_in_reviewer_wrapper() -> None:
    text = _read("scripts/reviewer_lan_genesis_rehearsal.sh")
    assert "@errol-genesis" not in text
    assert "c195d59d38ecf84b9baa227aff88960759afb72d2150f6e27a3187d0a3ae08be" not in text
