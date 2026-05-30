from __future__ import annotations

from pathlib import Path


def test_run_node_exports_repo_src_pythonpath_batch489() -> None:
    script = Path("scripts/run_node.sh").read_text(encoding="utf-8")

    assert 'REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"' in script
    assert 'export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH}"' in script
    assert 'export PYTHONPATH="${REPO_ROOT}/src"' in script
    assert "gunicorn weall.api.app:app" in script
