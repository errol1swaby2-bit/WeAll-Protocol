#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="${ROOT}/Weall-Protocol"
WEB="${ROOT}/web"
ARTIFACT_DIR="${WEALL_M2_ARTIFACT_DIR:-${ROOT}/artifacts/m2-closure/browser/async}"
if [[ -n "${WEALL_M2_ASYNC_DEVNET_DIR:-}" ]]; then
  DEVNET_DIR="${WEALL_M2_ASYNC_DEVNET_DIR}"
  RUNTIME_ROOT="$(dirname "${DEVNET_DIR}")"
  OWN_RUNTIME_ROOT=0
else
  RUNTIME_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/weall_m2_async_browser_XXXXXX")"
  DEVNET_DIR="${RUNTIME_ROOT}/.weall-devnet"
  OWN_RUNTIME_ROOT=1
fi
mkdir -p "${DEVNET_DIR}"
API_PORT="${WEALL_M2_ASYNC_API_PORT:-18101}"
API="http://127.0.0.1:${API_PORT}"
MANIFEST="${DEVNET_DIR}/m2-async-actors.json"
LOG="${ARTIFACT_DIR}/prepare.log"

mkdir -p "${ARTIFACT_DIR}"

cleanup() {
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${API_PORT}/tcp" >/dev/null 2>&1 || true
  fi
  if [[ "${WEALL_KEEP_M2_BROWSER_RUNTIME:-0}" != "1" ]]; then
    if [[ "${OWN_RUNTIME_ROOT}" == "1" ]]; then
      rm -rf "${RUNTIME_ROOT}" >/dev/null 2>&1 || true
    fi
  else
    echo "Kept async browser runtime: ${RUNTIME_ROOT}"
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -d "${WEB}/node_modules" ]]; then
  (cd "${WEB}" && npm ci)
fi

(
  cd "${BACKEND}"
  NODE1_API="${API}" \
  NODE1_BIND="127.0.0.1:${API_PORT}" \
  WEALL_API_BOOT_RUNTIME=1 \
  WEALL_DEVNET_DIR="${DEVNET_DIR}" \
  WEALL_DEVNET_KEEP_NODES=1 \
  WEALL_DEVNET_AUTOSTART_NODE2=0 \
  WEALL_DEVNET_RESET_ON_AUTOSTART=1 \
  WEALL_BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-500}" \
  WEALL_POH_ASYNC_N_JURORS="${WEALL_POH_ASYNC_N_JURORS:-1}" \
  WEALL_POH_ASYNC_MIN_REVIEWS="${WEALL_POH_ASYNC_MIN_REVIEWS:-1}" \
  WEALL_POH_ASYNC_APPROVAL_THRESHOLD="${WEALL_POH_ASYNC_APPROVAL_THRESHOLD:-1}" \
  WEALL_POH_ASYNC_REJECTION_THRESHOLD="${WEALL_POH_ASYNC_REJECTION_THRESHOLD:-1}" \
  WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1 \
  WEALL_POH_ENCRYPTED_LOCAL_STORE_ENABLED=1 \
  WEALL_MEDIA_CACHE_DIR="${DEVNET_DIR}/media-cache" \
  WEALL_EVIDENCE_PROVIDER_ID="@devnet-genesis" \
  WEALL_NATIVE_ASYNC_BROWSER_HANDOFF=1 \
  WEALL_M2_ACTOR_MANIFEST="${MANIFEST}" \
  bash scripts/devnet_full_onboarding_e2e.sh
) 2>&1 | tee "${LOG}"

test -s "${MANIFEST}" || { echo "ERROR: async actor manifest was not produced: ${MANIFEST}" >&2; exit 1; }
(
  cd "${WEB}"
  VITE_WEALL_DEV_PROXY_TARGET="${API}" \
  VITE_WEALL_API_BASE="${API}" \
  WEALL_REQUIRE_M2_REAL_STACK=1 \
  WEALL_M2_ACTOR_MANIFEST="${MANIFEST}" \
  WEALL_M2_BROWSER_TIMEOUT_MS="${WEALL_M2_BROWSER_TIMEOUT_MS:-600000}" \
  WEALL_M2_TRACE=1 \
  PLAYWRIGHT_OUTPUT_DIR="${ARTIFACT_DIR}/test-results" \
  PLAYWRIGHT_HTML_OUTPUT_DIR="${ARTIFACT_DIR}/playwright-report" \
  npm run test:m2-async-independent-browsers
) 2>&1 | tee "${ARTIFACT_DIR}/playwright.txt"

python3 - "${MANIFEST}" "${ARTIFACT_DIR}/actor-manifest.sanitized.json" <<'PY'
import json, pathlib, sys
source = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
data = json.loads(source.read_text())
# The public closure artifact must never contain recovery/private material.
out = {
    "schema_version": data.get("schema_version"),
    "kind": data.get("kind"),
    "api_base": data.get("api_base"),
    "case_id": data.get("case_id"),
    "applicant": data.get("applicant", {}).get("account"),
    "reviewers": [r.get("account") for r in data.get("reviewers", [])],
}
out_path.write_text(json.dumps(out, sort_keys=True, indent=2) + "\n")
PY

echo "OK: independent-browser async Tier 1 E2E passed"
