#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m3_common.sh"
m3_activate_venv
m3_require_command curl
m3_require_command node
m3_require_command npm

FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
MANIFEST="${WEALL_M3_ACTOR_MANIFEST:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
[[ -n "${MANIFEST}" && -f "${MANIFEST}" ]] || { echo "ERROR: WEALL_M3_ACTOR_MANIFEST must point to a schema-v3 actor manifest" >&2; exit 2; }
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
ART="${M3_ARTIFACT_ROOT}/browser/civic"
mkdir -p "${ART}"

python "${ROOT}/scripts/validate_m3_actor_manifest.py" \
  --manifest "${MANIFEST}" \
  --implementation-freeze "${FREEZE}" \
  --out-public-manifest "${M3_ARTIFACT_ROOT}/M3_ACTOR_MANIFEST.json" \
  --out-transcript "${ART}/transaction-transcript.json" \
  2>&1 | tee "${ART}/manifest-validation.txt"

readarray -t URLS < <(python - "${MANIFEST}" <<'PY'
import json, sys
obj=json.load(open(sys.argv[1], encoding='utf-8'))
print(str(obj['backend_base_url']).rstrip('/'))
print(str(obj.get('frontend_base_url') or 'http://127.0.0.1:5173').rstrip('/'))
PY
)
BACKEND_BASE="${URLS[0]}"
FRONTEND_BASE="${URLS[1]}"
curl -fsS "${BACKEND_BASE}/v1/status" > "${ART}/backend-status.json"
curl -fsS "${FRONTEND_BASE}/" > "${ART}/frontend-index.html"

if [[ ! -x "${M3_WEB}/node_modules/.bin/playwright" ]]; then
  echo "ERROR: frontend Playwright dependencies are incomplete; run scripts/bootstrap_m3_environment.sh" >&2
  exit 2
fi

(
  cd "${M3_WEB}"
  WEALL_M3_ACTOR_MANIFEST="${MANIFEST}" \
  M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
  PLAYWRIGHT_BASE_URL="${FRONTEND_BASE}" \
  PLAYWRIGHT_OUTPUT_DIR="${ART}/test-results" \
  PLAYWRIGHT_HTML_OUTPUT_DIR="${ART}/playwright-report" \
  npm run test:m3-civic-governance-real-stack
) 2>&1 | tee "${ART}/playwright.txt"
grep -q "1 passed" "${ART}/playwright.txt"
echo "OK: M3 signed real-stack actor journey passed"
