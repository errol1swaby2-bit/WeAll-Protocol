#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTER_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
WEB_DIR="${OUTER_ROOT}/web"

cd "${ROOT_DIR}"

run() {
  echo
  echo "=== $* ==="
  "$@"
}

echo "WeAll reviewer check"
echo "backend root: ${ROOT_DIR}"
echo "outer root:   ${OUTER_ROOT}"
echo
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "git branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "git commit: $(git rev-parse HEAD)"
  echo "git dirty status:"
  git status --short || true
else
  echo "git metadata: unavailable (archive snapshot or exported tree)"
fi

run python3 -S scripts/check_tx_canon_artifacts.py
run bash scripts/secret_guard.sh
run bash scripts/verify_release_dependencies.sh
run bash scripts/verify_release_tree.sh

# Target the milestone-critical guardrails first. The full pytest suite remains
# useful before release, but this keeps outside-reviewer smoke time bounded.
if command -v pytest >/dev/null 2>&1; then
  run pytest \
    tests/test_batch326_production_p0_p1_hardening.py \
    tests/test_batch327_vrf_manifest_fixture_compat.py \
    tests/test_reviewer_public_tx_ingress_security.py
else
  echo
  echo "WARN: pytest not found; skipping targeted backend tests" >&2
fi

if [ "${WEALL_SKIP_FRONTEND:-0}" = "1" ]; then
  echo
  echo "Skipping frontend checks because WEALL_SKIP_FRONTEND=1"
  exit 0
fi

if [ -f "${WEB_DIR}/package.json" ]; then
  cd "${WEB_DIR}"
  if [ ! -d node_modules ]; then
    run npm ci
  fi
  run npm run typecheck
  run npm run build
  run npm run production-safety-check
  echo
  echo "NOTE: npm run contract-check requires a running backend API."
  echo "      Start the backend and run: API_BASE=http://127.0.0.1:8000 npm run contract-check"
else
  echo
  echo "WARN: frontend package.json not found at ${WEB_DIR}; skipping frontend checks" >&2
fi

echo
echo "OK: reviewer smoke checks completed"
