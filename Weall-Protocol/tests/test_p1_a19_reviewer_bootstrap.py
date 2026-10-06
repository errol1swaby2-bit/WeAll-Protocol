from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "Weall-Protocol"


def test_a19_f002_tester_start_contract_requires_prepared_locked_environment() -> None:
    doc = (APP / "docs" / "TESTER_ONE_COMMAND_NODE_BOOT.md").read_text(encoding="utf-8")
    script = (APP / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert "One-command tester node start after prerequisites" in doc
    assert "not a blank-machine installer" in doc
    assert "pip install --require-hashes -r requirements.lock" in doc
    assert "pip install -e . --no-deps" in doc
    assert "verified external observer bundle" in doc
    assert "usable Genesis API base" in doc

    assert 'VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"' in script
    assert "prepared backend virtualenv missing" in script
    assert "npm is required for the default tester frontend path" in script
    assert 'if [ -x "${ROOT_DIR}/.venv/bin/python" ]' not in script


def test_a19_f003_fresh_clone_smoke_is_exact_commit_and_full_stack() -> None:
    script = (ROOT / "scripts" / "fresh_clone_smoke.sh").read_text(encoding="utf-8")

    assert 'REVIEW_COMMIT="${WEALL_FRESH_CLONE_COMMIT:-}"' in script
    assert "WEALL_FRESH_CLONE_COMMIT must be the exact 40-hex commit under review" in script
    assert 'git clone --no-checkout "$clone_url" "$WORKDIR"' in script
    assert 'git -C "$WORKDIR" fetch --depth 1 origin "$REVIEW_COMMIT"' in script
    assert 'git -C "$WORKDIR" checkout --detach "$REVIEW_COMMIT"' in script
    assert "require_cmd npm" in script
    assert "requirements-dev.lock" in script
    assert "pip install -e . --no-deps" in script
    assert "actual_tree=" in script
    assert "npm ci" in script
    assert "npm run typecheck" in script
    assert "npm run production-safety-check" in script
    assert "npm run build" in script
    assert "PASS_FULL_STACK" in script
    assert "tested tree:" in script
    assert "components run:" in script
    assert "components skipped: none" in script
    assert "skipping frontend build" not in script


def test_a19_f003_front_door_matches_exact_commit_smoke_contract() -> None:
    doc = (APP / "docs" / "reviewer" / "START_HERE.md").read_text(encoding="utf-8")

    assert "WEALL_FRESH_CLONE_COMMIT" in doc
    assert "exact 40-hex commit under review" in doc
    assert "moving default-branch HEAD" in doc
