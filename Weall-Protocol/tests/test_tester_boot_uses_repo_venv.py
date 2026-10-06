from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_boot_requires_prepared_repo_virtualenv() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert 'VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"' in script
    assert '[[ -x "${VENV_PYTHON}" ]] || fail "prepared backend virtualenv missing:' in script
    assert "install requirements.lock plus the local package first" in script
    assert 'export VIRTUAL_ENV="${ROOT_DIR}/.venv"' in script
    assert 'export PATH="${ROOT_DIR}/.venv/bin:${PATH}"' in script
    assert "Never fall back to ambient Python packages" in script
