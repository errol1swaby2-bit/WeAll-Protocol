#!/usr/bin/env bash
# Backend-directory compatibility wrapper. The canonical operator entrypoint lives at ../../scripts/run_clean_clone_go_gate_v1_5.sh.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
exec "${ROOT_DIR}/scripts/run_clean_clone_go_gate_v1_5.sh" "$@"
