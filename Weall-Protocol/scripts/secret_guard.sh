#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[secret-guard] scanning release-relevant files…"

fail() {
  echo "[secret-guard:FAIL] $*" >&2
  exit 1
}

TRACKED="$(mktemp)"
cleanup() {
  rm -f "$TRACKED"
}
trap cleanup EXIT

# Prefer Git's tracked-file set when available.  When this script is run from a
# release archive or CI artifact without .git metadata, fall back to scanning the
# export tree so release packaging cannot silently skip secret checks.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git ls-files > "$TRACKED"
  echo "[secret-guard] mode: git tracked files"
else
  echo "[secret-guard] WARN: not a git work tree; scanning exported tree instead."
  find . \
    -path './.git' -prune -o \
    -path './.venv' -prune -o \
    -path './node_modules' -prune -o \
    -path './web/node_modules' -prune -o \
    -type f -print | sed 's#^./##' > "$TRACKED"
fi

# 1) Hard fail if any .env or .env.* file is tracked/exported, except examples.
BAD_ENV_FILES="$(grep -E '(^|/)\.env(\..+)?$' "$TRACKED" | grep -vE '\.env\.example$' || true)"
if [[ -n "${BAD_ENV_FILES}" ]]; then
  echo "[secret-guard] env files found:"
  echo "${BAD_ENV_FILES}"
  fail "Do not commit or release .env files. Use .env.example templates only."
fi


# 1b) Hard fail on raw secret-key material under secrets/.  The only files
# allowed under secrets/ in a releasable/exported tree are documentation or
# ignore placeholders.  Public keys are intentionally excluded from release
# bundles too, because the authoritative public key is pinned in the production
# chain manifest.
BAD_SECRET_FILES="$(grep -E '(^|/)secrets/' "$TRACKED" | grep -vE '(^|/)secrets/(README(\.md)?|\.gitignore)$' || true)"
if [[ -n "${BAD_SECRET_FILES}" ]]; then
  echo "[secret-guard] raw secrets directory material found:"
  echo "${BAD_SECRET_FILES}"
  fail "Do not commit or release raw secrets/* material. Move node private/public key files outside the repo before packaging."
fi

# 2) Hard fail on local runtime secret/artifact paths that must never ship.
BAD_RUNTIME_PATHS="$(grep -E '(^|/)(\.weall-devnet|\.weall|data)(/|$)|(^|/)generated/demo_bootstrap_(secret|result)\.json$|(^|/)generated/.*secret.*\.json$|(^|/).*\.(db|db-wal|db-shm|sqlite)$' "$TRACKED" || true)"
if [[ -n "${BAD_RUNTIME_PATHS}" ]]; then
  echo "[secret-guard] forbidden local runtime or secret artifacts found:"
  echo "${BAD_RUNTIME_PATHS}"
  fail "Remove local runtime DBs, devnet state, and generated secret artifacts before commit/release."
fi

echo "[secret-guard] OK"
