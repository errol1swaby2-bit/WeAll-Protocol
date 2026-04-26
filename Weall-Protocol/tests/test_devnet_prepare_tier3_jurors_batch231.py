from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _text(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def test_prepare_tier3_jurors_script_is_syntax_valid_batch231() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(REPO_ROOT / "scripts/devnet_prepare_tier3_jurors.sh")],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_prepare_tier3_jurors_treats_placeholder_account_as_missing_batch231() -> None:
    script = _text("scripts/devnet_prepare_tier3_jurors.sh")
    assert "placeholder for unknown accounts" in script
    assert "has_key_material = False" in script
    assert "state.get('pubkey')" in script
    assert "state.get('pubkeys')" in script
    assert "state.get('active_keys')" in script
    assert "state.get('keys')" in script
    assert "if not has_key_material:" in script
    assert "print('missing')" in script


def test_prepare_tier3_jurors_registers_before_bootstrap_batch231() -> None:
    script = _text("scripts/devnet_prepare_tier3_jurors.sh")
    create_pos = script.index("devnet_create_account.sh")
    bootstrap_pos = script.index("devnet_bootstrap_tier3.sh")
    assert create_pos < bootstrap_pos
    assert "--fresh" in script
    assert "POH_BOOTSTRAP_TIER3_GRANT" in script
    assert "/v1/dev/demo-seed" not in script
    assert "demo-seed" not in script
