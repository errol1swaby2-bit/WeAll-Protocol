#!/usr/bin/env bash
set -euo pipefail

# Delete only an explicitly authorized controlled-devnet directory.
# The Python helper validates absolute paths, rejects symlink traversal,
# and uses directory-fd-relative symlink-resistant deletion on Linux.
#
# Default: backend/.weall-devnet (as before).
# Custom paths: require WEALL_DEVNET_RESET_ALLOWED_PARENT set to the
# exact trusted parent and WEALL_DEVNET_RESET_CONFIRM=I_CONFIRM_DELETE_CUSTOM_DEVNET.
#
# WARNING: destructive. Never run against a preserved rehearsal ledger.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"

python3 "${REPO_ROOT}/scripts/devnet_safe_paths.py" reset "${DEVNET_DIR}"

cat <<EOF
ok=true
devnet_dir=${DEVNET_DIR}
node1_dir=${DEVNET_DIR}/node1
node2_dir=${DEVNET_DIR}/node2
EOF
