from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _minimal_release_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "repo"
    (tree / "scripts").mkdir(parents=True)
    (tree / "generated").mkdir()
    (tree / "specs" / "tx_canon").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "clean_release_artifacts.sh", tree / "scripts" / "clean_release_artifacts.sh")
    shutil.copy2(ROOT / "scripts" / "verify_release_tree.sh", tree / "scripts" / "verify_release_tree.sh")
    (tree / "scripts" / "check_tx_canon_artifacts.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    (tree / "specs" / "tx_canon" / "tx_canon.yaml").write_text("version: test\n", encoding="utf-8")
    for name in ("tx_index.json", "helper_contract_map.json", "tx_contract_map.json"):
        (tree / "generated" / name).write_text("{}\n", encoding="utf-8")
    return tree


def test_clean_release_artifacts_removes_root_runtime_data_before_release_gate(tmp_path: Path) -> None:
    tree = _minimal_release_tree(tmp_path)
    (tree / "data").mkdir()
    (tree / "data" / "runtime.db").write_text("not for release\n", encoding="utf-8")
    (tree / ".weall-devnet").mkdir()
    (tree / ".weall-devnet" / "node.db.bft_journal.jsonl").write_text("journal\n", encoding="utf-8")
    (tree / "block.aux_helper_lanes").mkdir()

    failed = subprocess.run(
        ["bash", "scripts/verify_release_tree.sh"],
        cwd=str(tree),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert failed.returncode != 0
    assert "runtime data directories" in failed.stdout

    clean = subprocess.run(
        ["bash", "scripts/clean_release_artifacts.sh"],
        cwd=str(tree),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert clean.returncode == 0, clean.stdout
    assert "removed data" in clean.stdout
    assert "removed .weall-devnet" in clean.stdout

    verified = subprocess.run(
        ["bash", "scripts/verify_release_tree.sh"],
        cwd=str(tree),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert verified.returncode == 0, verified.stdout
    assert "release tree check passed" in verified.stdout
