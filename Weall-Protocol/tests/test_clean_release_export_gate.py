from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = BACKEND_ROOT.parent


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _copy_script(src_rel: str, dst_root: Path) -> None:
    src = OUTER_ROOT / src_rel
    dst = dst_root / src_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _make_minimal_outer_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "outer"
    backend = tree / "Weall-Protocol"
    web = tree / "web"

    for rel in [
        "scripts/build_clean_release_export.sh",
        "Weall-Protocol/scripts/clean_release_artifacts.sh",
        "Weall-Protocol/scripts/verify_release_tree.sh",
        "Weall-Protocol/scripts/secret_guard.sh",
        "Weall-Protocol/scripts/verify_release_dependencies.sh",
        "Weall-Protocol/scripts/verify_lockfiles.sh",
    ]:
        _copy_script(rel, tree)

    _write(backend / "specs/tx_canon/tx_canon.yaml", "transactions: []\n")
    _write(backend / "scripts/check_tx_canon_artifacts.py", "raise SystemExit(0)\n")
    for rel in ["tx_index.json", "helper_contract_map.json", "tx_contract_map.json"]:
        _write(backend / "generated" / rel, '{"canon":"preserve"}\n')

    hashed_req = "demo-pkg==1.0.0 \\\n    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    _write(backend / "requirements.lock", hashed_req)
    _write(backend / "requirements-dev.lock", hashed_req)
    _write(web / "package.json", '{"dependencies":{"vite":"7.3.3","typescript":"5.9.3","react":"18.3.1","react-dom":"18.3.1","react-router-dom":"6.30.3"}}\n')
    _write(web / "package-lock.json", '{"lockfileVersion":3,"packages":{}}\n')
    _write(tree / "scripts/fresh_clone_smoke.sh", "#!/usr/bin/env bash\n")
    return tree


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=merged,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def test_clean_release_export_gate_cleans_staged_copy_without_mutating_source(tmp_path: Path) -> None:
    tree = _make_minimal_outer_tree(tmp_path)
    backend = tree / "Weall-Protocol"
    web = tree / "web"

    # Release-forbidden artifacts in the source tree. The export gate must not
    # mutate the source; it must stage, clean, and verify a separate copy.
    _write(web / "tsconfig.tsbuildinfo", "ts cache\n")
    (web / "dist").mkdir()
    (backend / ".weall-devnet").mkdir()
    _write(backend / ".weall-devnet/local.json", "{}\n")
    _write(backend / ".weall-media-cache/aa/cached.bin", "local cache\n")
    (backend / "data").mkdir()
    _write(backend / "data/weall.db", "db\n")
    _write(backend / ".pytest-b333.db.bft_journal.jsonl", "{}\n")
    (backend / ".pytest-b333.aux_helper_lanes").mkdir()
    _write(backend / "artifact.rej", "reject\n")
    _write(backend / "secrets/weall_node_privkey", "private\n")

    verify_before = _run(["bash", "scripts/verify_release_tree.sh"], cwd=backend)
    assert verify_before.returncode != 0

    staging = tmp_path / "staging"
    result = _run(
        ["bash", "scripts/build_clean_release_export.sh", "--verify-only", "--keep-staging"],
        cwd=tree,
        env={"WEALL_RELEASE_STAGING": str(staging)},
    )

    assert result.returncode == 0, result.stdout
    assert "verify-only gate passed" in result.stdout

    # Source artifacts remain; the release gate must not silently alter the
    # operator working tree.
    assert (backend / "data/weall.db").exists()
    assert (backend / ".weall-media-cache/aa/cached.bin").exists()
    assert (web / "tsconfig.tsbuildinfo").exists()
    assert (backend / "secrets/weall_node_privkey").exists()

    staged = staging / "WeAll-Protocol"
    assert (staged / "Weall-Protocol/generated/tx_index.json").exists()
    assert (staged / "web/package-lock.json").exists()
    assert not (staged / "Weall-Protocol/data").exists()
    assert not (staged / "Weall-Protocol/.weall-media-cache").exists()
    assert not (staged / "web/dist").exists()
    assert not (staged / "web/tsconfig.tsbuildinfo").exists()
    assert not (staged / "Weall-Protocol/secrets/weall_node_privkey").exists()
    assert not (staged / "Weall-Protocol/artifact.rej").exists()


def test_clean_release_export_gate_rejects_internal_npm_registry(tmp_path: Path) -> None:
    tree = _make_minimal_outer_tree(tmp_path)
    _write(
        tree / "web/package-lock.json",
        '{"lockfileVersion":3,"packages":{"node_modules/vite":{"resolved":"https://packages.applied-caas-gateway1.internal.api.openai.org/artifactory/api/npm/npm-public/vite/-/vite.tgz"}}}\n',
    )

    result = _run(
        ["bash", "scripts/build_clean_release_export.sh", "--verify-only"],
        cwd=tree,
        env={"WEALL_RELEASE_STAGING": str(tmp_path / "staging")},
    )

    assert result.returncode != 0
    assert "sandbox-internal npm registry" in result.stdout


def test_clean_release_export_script_documents_no_source_mutation() -> None:
    text = (OUTER_ROOT / "scripts/build_clean_release_export.sh").read_text(encoding="utf-8")

    assert "source working tree is never mutated" in text
    assert "scripts/clean_release_artifacts.sh" in text
    assert "scripts/verify_release_tree.sh" in text
    assert "packages.applied-caas-gateway" in text
