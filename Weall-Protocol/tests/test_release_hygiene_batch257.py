from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def _make_minimal_release_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "repo"
    (tree / "scripts").mkdir(parents=True)
    (tree / "generated").mkdir()

    shutil.copy2(ROOT / "scripts/verify_release_tree.sh", tree / "scripts/verify_release_tree.sh")
    shutil.copy2(ROOT / "scripts/secret_guard.sh", tree / "scripts/secret_guard.sh")

    # verify_release_tree.sh requires these generated artifacts and calls this script.
    for rel in ["tx_index.json", "helper_contract_map.json", "tx_contract_map.json"]:
        (tree / "generated" / rel).write_text("{}\n", encoding="utf-8")
    (tree / "scripts/check_tx_canon_artifacts.py").write_text(
        "from __future__ import annotations\nraise SystemExit(0)\n",
        encoding="utf-8",
    )
    return tree


def _run(script: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script)],
        cwd=str(script.parent.parent),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def test_release_tree_rejects_demo_bootstrap_secret_batch257(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    (tree / "generated/demo_bootstrap_secret.json").write_text(
        '{"secret_key_b64":"not-for-release"}\n',
        encoding="utf-8",
    )

    result = _run(tree / "scripts/verify_release_tree.sh")

    assert result.returncode != 0
    assert "JSON secret artifacts" in result.stdout or "demo_bootstrap_secret" in result.stdout


def test_release_tree_rejects_local_runtime_artifacts_batch257(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    (tree / ".weall-devnet").mkdir()
    (tree / ".weall-devnet/genesis-operator.json").write_text(
        '{"private_key_hex":"not-for-release"}\n',
        encoding="utf-8",
    )
    (tree / "data").mkdir()
    (tree / "data/weall.db-wal").write_text("runtime wal\n", encoding="utf-8")

    result = _run(tree / "scripts/verify_release_tree.sh")

    assert result.returncode != 0
    assert "local devnet runtime directories" in result.stdout
    assert "runtime data directories" in result.stdout or "SQLite WAL files" in result.stdout



def test_release_tree_rejects_outer_web_typescript_build_artifact_batch316(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    outer = tree.parent
    web = outer / "web"
    web.mkdir()
    (web / "tsconfig.tsbuildinfo").write_text("local TypeScript build artifact\n", encoding="utf-8")

    result = _run(tree / "scripts/verify_release_tree.sh")

    assert result.returncode != 0
    assert "outer web TypeScript build info files" in result.stdout


def test_secret_guard_scans_export_tree_when_git_metadata_absent_batch257(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    (tree / "generated/demo_bootstrap_result.json").write_text(
        '{"session_key":"sess-not-for-release"}\n',
        encoding="utf-8",
    )

    result = _run(tree / "scripts/secret_guard.sh")

    assert result.returncode != 0
    assert "not a git work tree; scanning exported tree" in result.stdout
    assert "demo_bootstrap_result.json" in result.stdout


def test_release_package_excludes_known_local_secret_artifacts_batch257() -> None:
    text = (ROOT / "scripts/release_package.sh").read_text(encoding="utf-8")
    required_exclusions = [
        "'.weall-devnet/*'",
        "'data/*'",
        "'*.egg-info/*'",
        "'generated/demo_bootstrap_secret.json'",
        "'generated/demo_bootstrap_result.json'",
        "'generated/*secret*.json'",
        "'*.db-wal'",
        "'*.db-shm'",
    ]
    missing = [needle for needle in required_exclusions if needle not in text]
    assert not missing, f"release_package.sh missing exclusions: {missing}"


def test_frontend_route_registry_has_no_user_facing_tier3_gate_batch257() -> None:
    router = OUTER / "web/src/lib/router.ts"
    text = router.read_text(encoding="utf-8")

    assert "minPohTier: 3" not in text
    assert '"/juror"' not in text
    assert '"/tools"' not in text
    reviews_block = text.split('"/reviews":', 1)[1].split('"/reviews/:id":', 1)[0]
    assert "minPohTier: 2" in reviews_block
    assert "Exact reviewer lane responsibility" in reviews_block
    assert "Active Juror role or badge" not in text


def test_dockerfile_allows_dev_unlocked_builds_without_lockfiles_batch266() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "ARG ALLOW_UNLOCKED=0" in text
    assert "COPY requirements* /app/" in text
    assert "COPY requirements.lock requirements-dev.lock /app/" not in text
    assert "requirements.lock missing" in text
    assert 'ALLOW_UNLOCKED" = "1"' in text
