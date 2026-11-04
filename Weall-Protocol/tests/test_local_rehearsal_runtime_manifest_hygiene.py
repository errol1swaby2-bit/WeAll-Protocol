"""PR81: per-run public bootstrap manifests must never dirty tracked templates."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "Weall-Protocol" / "scripts" / "devnet_local_two_frontend_rehearsal.sh"
GENERATED_REL = "web/public/weall-local-rehearsal"
TRACKED = (
    "web/public/dev-bootstrap-genesis.json",
    "web/public/dev-bootstrap-observer.json",
)


def test_launcher_writes_only_ignored_per_run_bootstrap_manifest_paths() -> None:
    src = LAUNCHER.read_text(encoding="utf-8")
    assert 'BOOTSTRAP_PUBLIC_DIR="${WEB_ROOT}/public/weall-local-rehearsal"' in src
    assert 'GENESIS_MANIFEST="${BOOTSTRAP_PUBLIC_DIR}/dev-bootstrap-genesis.json"' in src
    assert 'OBSERVER_MANIFEST="${BOOTSTRAP_PUBLIC_DIR}/dev-bootstrap-observer.json"' in src
    assert 'VITE_WEALL_DEV_BOOTSTRAP_MANIFEST="/weall-local-rehearsal/dev-bootstrap-genesis.json"' in src
    assert 'VITE_WEALL_DEV_BOOTSTRAP_MANIFEST="/weall-local-rehearsal/dev-bootstrap-observer.json"' in src
    assert 'GENESIS_MANIFEST="${WEB_ROOT}/public/dev-bootstrap-genesis.json"' not in src
    assert 'OBSERVER_MANIFEST="${WEB_ROOT}/public/dev-bootstrap-observer.json"' not in src
    assert 'GENESIS_SECRET="${GENERATED_DIR}/dev-bootstrap-genesis-secret.json"' in src
    assert 'OBSERVER_SECRET="${GENERATED_DIR}/dev-bootstrap-observer-secret.json"' in src


def test_runtime_manifest_directory_is_gitignored_but_templates_remain_tracked() -> None:
    for filename in ("dev-bootstrap-genesis.json", "dev-bootstrap-observer.json"):
        candidate = f"{GENERATED_REL}/{filename}"
        ignored = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-q", candidate],
            check=False,
        )
        assert ignored.returncode == 0, candidate
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--", *TRACKED],
        capture_output=True,
        text=True,
        check=True,
    )
    assert set(result.stdout.splitlines()) == set(TRACKED)


def test_release_hygiene_checks_generated_manifest_directory() -> None:
    src = (ROOT / "Weall-Protocol" / "scripts" / "check_release_hygiene_v1_5.py").read_text(
        encoding="utf-8"
    )
    assert '"web/public/weall-local-rehearsal/"' in src
    assert "git_worktree_dirty" in src
    assert '--allow-dirty' in src  # Existing override remains explicit, not default.
