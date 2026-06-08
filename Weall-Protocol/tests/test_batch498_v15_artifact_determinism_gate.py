from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = [
    "generated/api_contract_map_v1_5.json",
    "generated/launch_disabled_matrix_v1_5.json",
    "generated/v15_implementation_gap_register.json",
]


def test_v15_generated_artifacts_are_gitignore_exempt_and_present_batch498() -> None:
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    lines = set(text.splitlines())
    assert "generated/*" in lines
    for rel in ARTIFACTS:
        assert f"!{rel}" in lines
        path = ROOT / rel
        assert path.is_file(), rel
        assert isinstance(json.loads(path.read_text(encoding="utf-8")), dict)


def test_v15_public_readiness_artifact_checker_passes_batch498() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_v15_public_readiness_artifacts.py"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout


def test_reviewer_gate_checks_generated_artifact_freshness_before_release_tree_batch498() -> None:
    text = (ROOT / "scripts/reviewer_production_readiness_gate.sh").read_text(encoding="utf-8")
    tx_idx = text.index("python3 -S scripts/check_tx_canon_artifacts.py")
    api_idx = text.index("python3 scripts/gen_api_contract_map.py --check")
    v15_idx = text.index("PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_v15_public_readiness_artifacts.py")
    release_idx = text.index("bash scripts/verify_release_tree.sh")
    targeted_idx = text.index("echo \"[reviewer-gate] targeted backend tests\"")
    assert tx_idx < api_idx < v15_idx < release_idx < targeted_idx
