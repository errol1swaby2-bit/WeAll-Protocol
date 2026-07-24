from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"


def _run(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def _load_contract() -> object:
    spec = importlib.util.spec_from_file_location("m2_evidence_contract_test", SCRIPTS / "m2_evidence_contract.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _state_summary() -> dict[str, object]:
    return {
        "schema_version": 1,
        "gate": "test",
        "source_log": "test.txt",
        "equal": True,
        "final": {
            "chain_id": "weall-controlled-devnet",
            "height": 12,
            "tip_hash": "a" * 64,
            "state_root": "b" * 64,
            "schema_version": "1",
            "tx_index_hash": "c" * 64,
            "protocol_profile_hash": "d" * 64,
        },
    }


def _marker_text(rule: dict[str, str]) -> str:
    if "contains" in rule:
        return rule["contains"] + "\n"
    # Every regex in the closure contract accepts this exact minimal success line.
    return "1 passed\n"


def _prepare_evidence_repo(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    for name in (
        "m2_evidence_contract.py",
        "build_m2_evidence_manifest.py",
        "check_m2_evidence_manifest.py",
    ):
        shutil.copy2(SCRIPTS / name, root / "scripts" / name)

    _run(root, "git", "init", "-q")
    _run(root, "git", "config", "user.email", "m2-test@example.com")
    _run(root, "git", "config", "user.name", "M2 Test")
    (root / "README.md").write_text("freeze\n", encoding="utf-8")
    _run(root, "git", "add", "README.md", "scripts")
    _run(root, "git", "commit", "-qm", "freeze")
    freeze = _run(root, "git", "rev-parse", "HEAD").stdout.strip()

    contract = _load_contract()
    artifact_paths = {str(item["evidence"]) for item in contract.COMMAND_LEDGER}
    artifact_paths.update(contract.STATE_SUMMARY_PATHS.values())
    artifact_paths.update(contract.TRANSCRIPT_PATHS)
    success_by_path = {rule["path"]: rule for rule in contract.SUCCESS_MARKERS}

    for rel in sorted(artifact_paths):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel in contract.STATE_SUMMARY_PATHS.values():
            path.write_text(json.dumps(_state_summary(), sort_keys=True, indent=2) + "\n", encoding="utf-8")
        else:
            rule = success_by_path.get(rel)
            path.write_text(_marker_text(rule) if rule else "closure artifact\n", encoding="utf-8")

    _run(
        root,
        sys.executable,
        "scripts/build_m2_evidence_manifest.py",
        "--freeze-commit",
        freeze,
        "--artifact-root",
        str(root / "artifacts" / "m2-closure"),
    )
    _run(root, "git", "add", "artifacts/m2-closure")
    return root, freeze


def test_state_root_summary_extractor_emits_last_equal_pair(tmp_path: Path) -> None:
    log = tmp_path / "roots.txt"
    out = tmp_path / "final-state.json"
    node = {
        "chain_id": "weall-controlled-devnet",
        "height": 9,
        "tip_hash": "1" * 64,
        "state_root": "2" * 64,
        "schema_version": "1",
        "tx_index_hash": "3" * 64,
        "protocol_profile_hash": "4" * 64,
    }
    log.write_text(
        "noise\n==> Node 1\n"
        + json.dumps(node, indent=2)
        + "\n==> Node 2\n"
        + json.dumps(node, indent=2)
        + "\n==> OK: node identities, tips, and state roots match\n",
        encoding="utf-8",
    )
    result = _run(
        REPO_ROOT,
        sys.executable,
        "scripts/extract_m2_state_root_summary.py",
        "--input",
        str(log),
        "--out",
        str(out),
        "--gate",
        "test-gate",
    )
    assert result.returncode == 0
    value = json.loads(out.read_text(encoding="utf-8"))
    assert value["equal"] is True
    assert value["final"]["state_root"] == node["state_root"]
    assert value["source_log"] == "roots.txt"


def test_state_root_summary_extractor_rejects_mismatch(tmp_path: Path) -> None:
    log = tmp_path / "roots.txt"
    out = tmp_path / "final-state.json"
    left = {
        "chain_id": "weall-controlled-devnet",
        "height": 9,
        "tip_hash": "1" * 64,
        "state_root": "2" * 64,
        "schema_version": "1",
        "tx_index_hash": "3" * 64,
        "protocol_profile_hash": "4" * 64,
    }
    right = dict(left, state_root="5" * 64)
    log.write_text(
        "==> Node 1\n"
        + json.dumps(left, indent=2)
        + "\n==> Node 2\n"
        + json.dumps(right, indent=2)
        + "\n",
        encoding="utf-8",
    )
    result = _run(
        REPO_ROOT,
        sys.executable,
        "scripts/extract_m2_state_root_summary.py",
        "--input",
        str(log),
        "--out",
        str(out),
        "--gate",
        "test-gate",
        check=False,
    )
    assert result.returncode != 0
    assert "m2_state_root_pair_mismatch" in result.stdout


def test_evidence_manifest_checker_accepts_exact_staged_tree(tmp_path: Path) -> None:
    root, freeze = _prepare_evidence_repo(tmp_path)
    result = _run(
        root,
        sys.executable,
        "scripts/check_m2_evidence_manifest.py",
        "--mode",
        "staged",
        "--freeze-commit",
        freeze,
    )
    assert "OK: M2 evidence manifest verified" in result.stdout


def test_evidence_manifest_checker_rejects_hash_tampering(tmp_path: Path) -> None:
    root, freeze = _prepare_evidence_repo(tmp_path)
    target = root / "artifacts/m2-closure/backend/pytest.txt"
    target.write_text("999 passed\npost-build tamper\n", encoding="utf-8")
    _run(root, "git", "add", str(target.relative_to(root)))
    result = _run(
        root,
        sys.executable,
        "scripts/check_m2_evidence_manifest.py",
        "--mode",
        "staged",
        "--freeze-commit",
        freeze,
        check=False,
    )
    assert result.returncode != 0
    assert "m2_evidence_size_mismatch" in result.stdout or "m2_evidence_sha256_mismatch" in result.stdout


def test_evidence_manifest_checker_rejects_private_material_even_with_matching_hash(tmp_path: Path) -> None:
    root, freeze = _prepare_evidence_repo(tmp_path)
    target_rel = "artifacts/m2-closure/backend/pytest.txt"
    target = root / target_rel
    private_bytes = b'1 passed\n{"private_key":"must-not-commit"}\n'
    target.write_bytes(private_bytes)
    manifest_path = root / "artifacts/m2-closure/M2_EVIDENCE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(item for item in manifest["files"] if item["path"] == target_rel)
    entry["size_bytes"] = len(private_bytes)
    entry["sha256"] = hashlib.sha256(private_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    _run(root, "git", "add", "artifacts/m2-closure")
    result = _run(
        root,
        sys.executable,
        "scripts/check_m2_evidence_manifest.py",
        "--mode",
        "staged",
        "--freeze-commit",
        freeze,
        check=False,
    )
    assert result.returncode != 0
    assert "m2_evidence_private_material" in result.stdout


def test_evidence_manifest_checker_rejects_manifest_path_omission(tmp_path: Path) -> None:
    root, freeze = _prepare_evidence_repo(tmp_path)
    manifest_path = root / "artifacts/m2-closure/M2_EVIDENCE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = manifest["files"][1:]
    manifest["artifact_count"] = len(manifest["files"])
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    _run(root, "git", "add", "artifacts/m2-closure")
    result = _run(
        root,
        sys.executable,
        "scripts/check_m2_evidence_manifest.py",
        "--mode",
        "staged",
        "--freeze-commit",
        freeze,
        check=False,
    )
    assert result.returncode != 0
    assert "m2_evidence_manifest_path_set_mismatch" in result.stdout


def test_evidence_manifest_builder_rejects_missing_success_marker(tmp_path: Path) -> None:
    root, freeze = _prepare_evidence_repo(tmp_path)
    target = root / "artifacts/m2-closure/backend/pytest.txt"
    target.write_text("test process exited without a success summary\n", encoding="utf-8")
    result = _run(
        root,
        sys.executable,
        "scripts/build_m2_evidence_manifest.py",
        "--freeze-commit",
        freeze,
        "--artifact-root",
        str(root / "artifacts" / "m2-closure"),
        check=False,
    )
    assert result.returncode != 0
    assert "m2_evidence_success_regex_missing" in result.stdout


def test_evidence_manifest_checker_accepts_exact_direct_child_commit(tmp_path: Path) -> None:
    root, freeze = _prepare_evidence_repo(tmp_path)
    _run(root, "git", "commit", "-qm", "m2 evidence")
    result = _run(
        root,
        sys.executable,
        "scripts/check_m2_evidence_manifest.py",
        "--mode",
        "commit",
        "--freeze-commit",
        freeze,
        "--commit",
        "HEAD",
    )
    assert "OK: M2 evidence manifest verified" in result.stdout
