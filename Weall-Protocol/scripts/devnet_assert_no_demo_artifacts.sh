#!/usr/bin/env bash
set -euo pipefail

# Static release/devnet hygiene guard. It fails when demo seed outputs or
# frontend bootstrap seed files are present in a package meant for controlled
# multi-node participant testing.
#
# Set WEALL_ALLOW_DEVNET_WORKDIR=1 to permit a live local .weall-devnet workdir
# while still rejecting browser/demo seed artifacts.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

allow_workdir="${WEALL_ALLOW_DEVNET_WORKDIR:-0}"
case "${allow_workdir}" in
  1|true|TRUE|yes|YES|on|ON) allow_workdir=1 ;;
  *) allow_workdir=0 ;;
esac

fail=0
check_path() {
  local path="$1"
  local reason="$2"
  if [[ -e "${path}" ]]; then
    echo "ERROR: controlled-devnet package contains ${reason}: ${path}" >&2
    fail=1
  fi
}

check_path "generated/demo_bootstrap_result.json" "demo bootstrap result"
check_path "web/public/dev-bootstrap.json" "frontend dev bootstrap seed"
check_path "web/public/seeds.json" "frontend seed manifest"

if [[ "${allow_workdir}" != "1" ]]; then
  check_path ".weall-devnet" "local devnet runtime state"
fi

while IFS= read -r -d '' p; do
  echo "ERROR: controlled-devnet package contains pytest/runtime artifact: ${p}" >&2
  fail=1
done < <(find . -maxdepth 1 -type d -name '.pytest-*' -print0)

if [[ "${fail}" != "0" ]]; then
  exit 2
fi

echo "controlled-devnet demo artifact guard: ok"
