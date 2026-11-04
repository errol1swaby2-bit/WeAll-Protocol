"""Regression checks for controlled-devnet first-run directory permissions."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "devnet_safe_paths.py"
SPEC = importlib.util.spec_from_file_location("weall_devnet_safe_paths_permissions", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SAFE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAFE)


def test_missing_devnet_requires_writable_parent() -> None:
    with TemporaryDirectory() as tmp:
        target = Path(tmp) / ".weall-devnet"
        with patch.object(SAFE.os, "access", return_value=False):
            with pytest.raises(SAFE.UnsafeDevnetPath, match="devnet_not_writable"):
                SAFE.ensure_devnet_writable(str(target))
        assert not target.exists(), "read-only preflight must not create a directory"


def test_existing_devnet_requires_writable_directory_not_just_parent() -> None:
    with TemporaryDirectory() as tmp:
        target = Path(tmp) / ".weall-devnet"
        target.mkdir()
        with patch.object(SAFE.os, "access", return_value=False):
            with pytest.raises(SAFE.UnsafeDevnetPath) as exc:
                SAFE.ensure_devnet_writable(str(target))
        message = str(exc.value)
        assert f"devnet_not_writable:{target}" in message
        assert "do not run sudo on the launcher" in message
        assert target.exists(), "preflight must not delete runtime state"


def test_writable_devnet_has_no_side_effects() -> None:
    with TemporaryDirectory() as tmp:
        target = Path(tmp) / ".weall-devnet"
        target.mkdir()
        marker = target / "preserve-this-file"
        marker.write_text("preserve", encoding="utf-8")
        with patch.object(SAFE.os, "access", return_value=True):
            assert SAFE.ensure_devnet_writable(str(target)) == target
        assert marker.read_text(encoding="utf-8") == "preserve"


def test_symlink_devnet_still_rejected_before_access_check() -> None:
    with TemporaryDirectory() as tmp:
        parent = Path(tmp)
        (parent / "storage").mkdir()
        (parent / ".weall-devnet").symlink_to(parent / "storage", target_is_directory=True)
        with pytest.raises(SAFE.UnsafeDevnetPath, match="symlink_component"):
            SAFE.ensure_devnet_writable(str(parent / ".weall-devnet"))


def test_launcher_preflight_before_runtime_mkdir_and_truthful_no_pid_message() -> None:
    script = (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")
    check = 'python3 scripts/devnet_safe_paths.py check-devnet-writable "\x24{DEVNET_DIR}" >/dev/null'
    mkdir = 'mkdir -p "\x24{LOG_DIR}" "\x24{GENERATED_DIR}" "\x24{DEVNET_DIR}/accounts" "\x24{WEB_ROOT}/public" "\x24{RUNTIME_DIR}"'
    assert check in script
    assert mkdir in script
    assert script.index(check) < script.index(mkdir)
    assert "Local rehearsal processes left running:" not in script
    assert "exited before starting any WeAll node/frontend processes" in script
