#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${WEALL_REVIEWER_VENV_DIR:-${ROOT_DIR}/.venv}"
RUN_SECRET_GUARD="${WEALL_REVIEWER_SETUP_SECRET_GUARD:-1}"
RUN_DEP_CHECK="${WEALL_REVIEWER_SETUP_DEP_CHECK:-1}"
RUN_TX_CANON="${WEALL_REVIEWER_SETUP_TX_CANON:-1}"
RUN_RELEASE_TREE="${WEALL_REVIEWER_SETUP_RELEASE_TREE:-0}"

truthy() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  fail "python3 is required"
fi

if [ ! -d "${VENV_DIR}" ]; then
  echo "[reviewer-setup] creating virtual environment: ${VENV_DIR}"
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

python3 -m pip install -r requirements-dev.lock
python3 -m pip install -e .

python3 - <<'PY'
from __future__ import annotations
import weall
print(f"OK: imported weall from {weall.__file__}")
PY

if truthy "${RUN_TX_CANON}"; then
  python3 -B -S scripts/check_tx_canon_artifacts.py
fi

if truthy "${RUN_SECRET_GUARD}"; then
  bash scripts/secret_guard.sh
fi

if truthy "${RUN_DEP_CHECK}"; then
  bash scripts/verify_release_dependencies.sh
fi

if truthy "${RUN_RELEASE_TREE}"; then
  cat <<'MSG'
[reviewer-setup] Running release-tree check because WEALL_REVIEWER_SETUP_RELEASE_TREE=1.
[reviewer-setup] This check may fail after local install or runtime boot artifacts exist.
MSG
  bash scripts/verify_release_tree.sh
else
  cat <<'MSG'
[reviewer-setup] Skipping release-tree check by default.
[reviewer-setup] Reason: reviewer setup installs the local package and may create local/runtime artifacts.
[reviewer-setup] For release hygiene, run scripts/verify_release_tree.sh separately on a cleaned tree.
MSG
fi

cat <<MSG
OK: reviewer setup environment is ready
- repo: ${ROOT_DIR}
- virtualenv: ${VENV_DIR}
- package import: weall
- tx canon / secret / dependency checks completed according to toggles
MSG
