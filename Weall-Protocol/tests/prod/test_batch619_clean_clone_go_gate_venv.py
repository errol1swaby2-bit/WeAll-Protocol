from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTER_ROOT = ROOT.parent
SCRIPT = OUTER_ROOT / "scripts" / "run_clean_clone_go_gate_v1_5.sh"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_batch619_clean_clone_gate_uses_backend_virtualenv_before_install() -> None:
    text = _script()

    assert 'BACKEND_VENV_DIR="${BACKEND_VENV_DIR:-${BACKEND_DIR}/.venv}"' in text
    assert "ensure_backend_venv()" in text
    assert 'run_backend "${HOST_PYTHON_BIN}" -m venv "${BACKEND_VENV_DIR}"' in text
    assert 'export VIRTUAL_ENV="${BACKEND_VENV_DIR}"' in text
    assert 'export PATH="${BACKEND_VENV_DIR}/bin:${PATH}"' in text

    assert text.index("ensure_backend_venv") < text.index('echo "== Installing backend dependencies =="')
    assert 'run_backend "${PYTHON_BIN}" -m pip install -r requirements-dev.lock' in text


def test_batch619_clean_clone_gate_documents_no_manual_activation_needed() -> None:
    text = _script()

    assert "creates/uses the backend .venv" in text
    assert "installs backend dependencies inside" in text
    assert "The script still creates/uses the backend .venv for checks." in text
    assert "--venv-dir DIR" in text
    assert "sudo apt install python3-venv" in text
