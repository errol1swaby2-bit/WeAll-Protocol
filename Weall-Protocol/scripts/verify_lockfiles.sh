#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

check_one() {
  local f="$1"
  [[ -f "$f" ]] || fail "$f missing"

  if grep -qE '^\s*-r\s+requirements\.in\s*$' "$f"; then
    fail "$f looks like a placeholder (-r requirements.in). Run ./scripts/lock_deps.sh"
  fi

  if ! grep -qE '^[a-zA-Z0-9_.-]+==[0-9]' "$f"; then
    fail "$f does not appear to contain pinned requirements (name==version)."
  fi

  # If we ever enforce --require-hashes in prod, lockfiles must include hashes.
  if ! grep -qE '^\s*--hash=sha256:' "$f"; then
    fail "$f does not contain package hashes (--hash=sha256:...). Re-generate with ./scripts/lock_deps.sh"
  fi
}

check_one "requirements.lock"
check_one "requirements-dev.lock"

echo "OK: lockfiles are present, pinned, and hashed."
