#!/usr/bin/env bash
set -euo pipefail

M2_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M2_BACKEND="${M2_ROOT}/Weall-Protocol"
M2_WEB="${M2_ROOT}/web"
M2_ARTIFACT_ROOT="${WEALL_M2_ARTIFACT_ROOT:-${M2_ROOT}/artifacts/m2-closure}"

m2_activate_venv() {
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    return 0
  fi
  local candidate
  for candidate in "${M2_ROOT}/.venv/bin/activate" "${M2_BACKEND}/.venv/bin/activate" "${HOME}/.venv/bin/activate"; do
    if [[ -f "${candidate}" ]]; then
      # shellcheck disable=SC1090
      source "${candidate}"
      return 0
    fi
  done
  echo "ERROR: no Python virtualenv is active and no supported activation file was found." >&2
  echo "Checked: ${M2_ROOT}/.venv, ${M2_BACKEND}/.venv, ${HOME}/.venv" >&2
  exit 2
}

m2_require_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing required command: $1" >&2; exit 2; }
}

m2_new_runtime() {
  local label="$1"
  local parent
  parent="$(mktemp -d "${TMPDIR:-/tmp}/weall_m2_${label}_XXXXXX")"
  mkdir -p "${parent}/.weall-devnet"
  printf '%s\n' "${parent}"
}

m2_sanitize_artifacts() {
  local root="$1"
  python3 - "${root}" <<'PY'
from __future__ import annotations
import re
import sys
from pathlib import Path
root = Path(sys.argv[1])
if not root.exists():
    raise SystemExit(0)
patterns = [
    re.compile(r'"(?:private_key|private_key_hex|secretKeyB64|secret_key|recoveryAuthoritySecretKeyB64|evidenceKemSecretKeyB64)"\s*:', re.I),
    re.compile(r'BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY'),
]
violations = []
for path in sorted(p for p in root.rglob('*') if p.is_file()):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        continue
    for pattern in patterns:
        if pattern.search(text):
            violations.append(str(path))
            break
if violations:
    raise SystemExit('private_material_detected_in_m2_artifacts:' + ','.join(violations))
print(f'OK: no private key material detected under {root}')
PY
}
