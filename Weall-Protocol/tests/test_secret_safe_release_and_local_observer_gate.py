from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _make_minimal_release_tree(tmp_path: Path, *, include_secret_guard: bool = True) -> Path:
    tree = tmp_path / "repo"
    (tree / "scripts").mkdir(parents=True)
    (tree / "generated").mkdir()
    shutil.copy2(ROOT / "scripts" / "verify_release_tree.sh", tree / "scripts" / "verify_release_tree.sh")
    if include_secret_guard:
        shutil.copy2(ROOT / "scripts" / "secret_guard.sh", tree / "scripts" / "secret_guard.sh")
    for rel in ["tx_index.json", "helper_contract_map.json", "tx_contract_map.json"]:
        (tree / "generated" / rel).write_text("{}\n", encoding="utf-8")
    (tree / "scripts/check_tx_canon_artifacts.py").write_text(
        "from __future__ import annotations\nraise SystemExit(0)\n",
        encoding="utf-8",
    )
    return tree


def _run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def test_verify_release_tree_rejects_raw_secrets_directory_material(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    (tree / "secrets").mkdir()
    (tree / "secrets/README.md").write_text("local secret placeholder docs\n", encoding="utf-8")
    (tree / "secrets/.gitignore").write_text("*\n", encoding="utf-8")
    (tree / "secrets/weall_node_privkey").write_text("not-for-release\n", encoding="utf-8")
    (tree / "secrets/weall_node_pubkey").write_text("public-but-local\n", encoding="utf-8")

    result = _run(["bash", "scripts/verify_release_tree.sh"], cwd=tree)

    assert result.returncode != 0
    assert "raw secrets directory material" in result.stdout
    assert "secrets/weall_node_privkey" in result.stdout
    assert "secrets/weall_node_pubkey" in result.stdout


def test_verify_release_tree_allows_only_secret_placeholders(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    (tree / "secrets").mkdir()
    (tree / "secrets/README.md").write_text("Store local keys outside release artifacts.\n", encoding="utf-8")
    (tree / "secrets/.gitignore").write_text("*\n!.gitignore\n!README.md\n", encoding="utf-8")

    result = _run(["bash", "scripts/verify_release_tree.sh"], cwd=tree)

    assert result.returncode == 0, result.stdout
    assert "no raw secrets directory material" in result.stdout


def test_secret_guard_rejects_raw_secret_paths_in_export_tree(tmp_path: Path) -> None:
    tree = _make_minimal_release_tree(tmp_path)
    (tree / "secrets").mkdir()
    (tree / "secrets/weall_node_privkey").write_text("not-for-release\n", encoding="utf-8")

    result = _run(["bash", "scripts/secret_guard.sh"], cwd=tree)

    assert result.returncode != 0
    assert "not a git work tree; scanning exported tree" in result.stdout
    assert "raw secrets directory material" in result.stdout
    assert "secrets/weall_node_privkey" in result.stdout


def test_release_package_excludes_secrets_even_after_verify_gate() -> None:
    text = (ROOT / "scripts/release_package.sh").read_text(encoding="utf-8")

    assert "'secrets/*'" in text
    assert '"$ROOT/scripts/clean_release_artifacts.sh"' in text
    assert '"$ROOT/scripts/verify_release_tree.sh"' in text


def test_clean_release_artifacts_refuses_to_silently_delete_secret_material() -> None:
    text = (ROOT / "scripts/clean_release_artifacts.sh").read_text(encoding="utf-8")

    assert "Raw node/operator keys are intentionally not deleted automatically" in text
    assert "release verification will fail" in text
    assert 'rm_path "secrets"' not in text
    assert "rm -rf -- \"secrets\"" not in text


def test_local_observer_readiness_gate_passes_without_second_machine() -> None:
    result = _run(["bash", "scripts/local_observer_readiness_gate.sh"], cwd=ROOT)

    assert result.returncode == 0, result.stdout
    assert "local observer readiness gate passed" in result.stdout
    assert "This is not a substitute for scripts/rehearse_external_observer_two_machine.sh" in result.stdout
    assert "validator signing, BFT, helper authority, and block loop are disabled" in result.stdout
