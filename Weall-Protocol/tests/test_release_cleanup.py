from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _make_release_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "repo"
    (tree / "scripts").mkdir(parents=True)
    (tree / "generated").mkdir()
    (tree / "specs/tx_canon").mkdir(parents=True)
    (tree / "specs/tx_canon/tx_canon.yaml").write_text("transactions: []\n", encoding="utf-8")

    for script in [
        "clean_release_artifacts.sh",
        "verify_release_tree.sh",
    ]:
        shutil.copy2(ROOT / "scripts" / script, tree / "scripts" / script)

    for rel in ["tx_index.json", "helper_contract_map.json", "tx_contract_map.json"]:
        (tree / "generated" / rel).write_text('{"canon":"preserve"}\n', encoding="utf-8")
    (tree / "scripts/check_tx_canon_artifacts.py").write_text(
        "from __future__ import annotations\nraise SystemExit(0)\n",
        encoding="utf-8",
    )
    return tree


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script), *args],
        cwd=str(script.parent.parent),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def test_clean_release_artifacts_removes_verify_release_tree_blockers(tmp_path: Path) -> None:
    tree = _make_release_tree(tmp_path)
    outer_web = tree.parent / "web"
    outer_web.mkdir()

    # Artifacts currently rejected by scripts/verify_release_tree.sh.
    (tree / "src/weall_protocol.egg-info").mkdir(parents=True)
    (tree / ".weall-devnet").mkdir()
    (tree / ".weall-devnet/local.json").write_text("{}\n", encoding="utf-8")
    (tree / "data").mkdir()
    (tree / "data/weall.db-wal").write_text("wal\n", encoding="utf-8")
    (tree / ".pytest-b314.db.bft_journal.jsonl").write_text("{}\n", encoding="utf-8")
    (tree / ".pytest-b314.aux_helper_lanes").mkdir()
    (tree / ".pytest_cache").mkdir()
    (tree / "generated/demo_bootstrap_secret.json").write_text("{}\n", encoding="utf-8")
    (outer_web / "tsconfig.tsbuildinfo").write_text("ts cache\n", encoding="utf-8")
    (outer_web / "dist").mkdir()

    before = _run(tree / "scripts/verify_release_tree.sh")
    assert before.returncode != 0
    assert "release tree check FAILED" in before.stdout

    clean = _run(tree / "scripts/clean_release_artifacts.sh")
    assert clean.returncode == 0, clean.stdout

    after = _run(tree / "scripts/verify_release_tree.sh")
    assert after.returncode == 0, after.stdout
    assert "release tree check passed" in after.stdout

    # Canon-generated artifacts must not be deleted by cleanup.
    for rel in ["tx_index.json", "helper_contract_map.json", "tx_contract_map.json"]:
        assert (tree / "generated" / rel).read_text(encoding="utf-8") == '{"canon":"preserve"}\n'


def test_clean_release_artifacts_dry_run_does_not_remove(tmp_path: Path) -> None:
    tree = _make_release_tree(tmp_path)
    (tree / "data").mkdir()
    (tree / "data/weall.db").write_text("db\n", encoding="utf-8")

    result = _run(tree / "scripts/clean_release_artifacts.sh", "--dry-run")

    assert result.returncode == 0, result.stdout
    assert "would remove data" in result.stdout
    assert (tree / "data/weall.db").exists()


def test_release_package_uses_release_artifact_cleanup() -> None:
    text = (ROOT / "scripts/release_package.sh").read_text(encoding="utf-8")

    assert '"$ROOT/scripts/clean_release_artifacts.sh"' in text
    assert '"$ROOT/scripts/clean_repo.sh"' not in text
    assert '"$ROOT/scripts/verify_release_tree.sh"' in text
