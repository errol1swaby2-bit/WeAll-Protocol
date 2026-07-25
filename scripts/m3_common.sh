#!/usr/bin/env bash
set -euo pipefail

M3_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M3_BACKEND="${M3_ROOT}/Weall-Protocol"
M3_WEB="${M3_ROOT}/web"
M3_ARTIFACT_ROOT="${WEALL_M3_EVIDENCE_DIR:-${M3_ROOT}/artifacts/m3-closure}"

m3_activate_venv() {
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    return 0
  fi
  local candidate
  for candidate in "${M3_ROOT}/.venv-m3/bin/activate" "${M3_ROOT}/.venv/bin/activate" "${M3_BACKEND}/.venv/bin/activate" "${HOME}/.venv/bin/activate"; do
    if [[ -f "${candidate}" ]]; then
      # shellcheck disable=SC1090
      source "${candidate}"
      return 0
    fi
  done
  echo "ERROR: no supported Python virtualenv was found for M3 closure." >&2
  echo "Run: scripts/bootstrap_m3_environment.sh" >&2
  exit 2
}

m3_require_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing required command: $1" >&2; exit 2; }
}

m3_new_runtime() {
  local label="$1"
  local parent
  parent="$(mktemp -d "${TMPDIR:-/tmp}/weall_m3_${label}_XXXXXX")"
  mkdir -p "${parent}/.weall-devnet"
  printf '%s\n' "${parent}"
}

m3_run_logged() {
  local log="$1"; shift
  mkdir -p "$(dirname "${log}")"
  set -o pipefail
  "$@" 2>&1 | tee "${log}"
}
