from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _text(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def test_prepare_live_jurors_script_is_syntax_valid() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(REPO_ROOT / "scripts/devnet_prepare_live_jurors.sh")],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_prepare_live_jurors_treats_placeholder_account_as_missing() -> None:
    script = _text("scripts/devnet_prepare_live_jurors.sh")
    assert "placeholder for unknown accounts" in script
    assert "has_key_material = False" in script
    assert "state.get('pubkey')" in script
    assert "state.get('pubkeys')" in script
    assert "state.get('active_keys')" in script
    assert "state.get('keys')" in script
    assert "if not has_key_material:" in script
    assert '"missing": True' in script


def test_prepare_live_jurors_verifies_genesis_reviewer_without_self_grant() -> None:
    script = _text("scripts/devnet_prepare_live_jurors.sh")
    assert "GENESIS_REVIEWER_ACCOUNT" in script
    assert "GENESIS_REVIEWER_KEYFILE" in script
    assert "Deterministic genesis-bound Live reviewer ready" in script
    assert "No open bootstrap or runtime reviewer self-grant was used" in script
    assert "devnet_create_account.sh" not in script
    assert "devnet_bootstrap_live.sh" not in script
    assert "POH_BOOTSTRAP_TIER2_GRANT" not in script
    assert "/v1/dev/demo-seed" not in script
    assert "demo-seed" not in script
