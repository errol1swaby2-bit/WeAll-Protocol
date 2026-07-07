from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_boot_uses_repo_virtualenv_when_present() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert 'if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then' in script
    assert 'export VIRTUAL_ENV="${ROOT_DIR}/.venv"' in script
    assert 'export PATH="${ROOT_DIR}/.venv/bin:${PATH}"' in script
    assert "Fresh-clone testers should not need to remember to activate .venv manually" in script
