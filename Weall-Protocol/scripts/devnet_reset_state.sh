#!/usr/bin/env bash
set -euo pipefail

# Reset only the controlled multi-node devnet work directory.
# Refuses to delete arbitrary paths unless the target basename is .weall-devnet.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"

base="$(basename "${DEVNET_DIR}")"
if [[ "${base}" != ".weall-devnet" ]]; then
  echo "ERROR: refusing to delete non-devnet directory: ${DEVNET_DIR}" >&2
  echo "Set WEALL_DEVNET_DIR to a path whose basename is .weall-devnet." >&2
  exit 2
fi

rm -rf "${DEVNET_DIR}"
mkdir -p "${DEVNET_DIR}/node1" "${DEVNET_DIR}/node2"

cat <<EOF
ok=true
devnet_dir=${DEVNET_DIR}
node1_dir=${DEVNET_DIR}/node1
node2_dir=${DEVNET_DIR}/node2
EOF
