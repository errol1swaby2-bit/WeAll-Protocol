#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${WORKSPACE_DIR}/Weall-Protocol"
WEB_DIR="${WEALL_WEB_DIR:-${WORKSPACE_DIR}/web}"
VENV_DIR="${WEALL_M3_VENV:-${WORKSPACE_DIR}/.venv-m3}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

"${PYTHON_BIN}" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit(f"Python 3.12+ is required; found {sys.version.split()[0]}")
PY

if [[ ! -d "${VENV_DIR}" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip setuptools wheel

PIP_ARGS=(--require-hashes -r "${BACKEND_DIR}/requirements-dev.lock")
if [[ -n "${WEALL_WHEELHOUSE:-}" ]]; then
  PIP_ARGS=(--no-index --find-links "${WEALL_WHEELHOUSE}" "${PIP_ARGS[@]}")
fi
python -m pip install "${PIP_ARGS[@]}"

if [[ ! -f "${WEB_DIR}/package-lock.json" ]]; then
  echo "Missing frontend lockfile: ${WEB_DIR}/package-lock.json" >&2
  exit 1
fi
(
  cd "${WEB_DIR}"
  npm ci
)

(
  cd "${WORKSPACE_DIR}"
  PYTHONPATH=Weall-Protocol/src python scripts/check_m3_dependencies.py
)

echo "M3 environment ready: ${VENV_DIR}"
