#!/usr/bin/env bash
# Backend-directory compatibility wrapper. The canonical frontend/backend contract entrypoint lives at ../../scripts/run_frontend_contract_check_with_backend.sh.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
exec "${ROOT_DIR}/scripts/run_frontend_contract_check_with_backend.sh" "$@"
