#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv-release-check"
API_URL="${WEALL_API:-http://127.0.0.1:8000}"
CHAIN_ID="${WEALL_CHAIN_ID:-weall-dev}"
ACCOUNT="${WEALL_ACCOUNT:-@demo_tester}"
POST_BODY="${WEALL_POST_BODY:-External tester demo post}"
MEDIA_TEXT="${WEALL_MEDIA_TEXT:-hello from external tester demo}"
FEED_URL="${WEALL_FEED_URL:-http://127.0.0.1:5173}"

cd "${ROOT_DIR}"
mkdir -p generated

if [ ! -d "${VENV_DIR}" ]; then
  python3 -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip wheel >/dev/null
python -m pip install -e . >/dev/null

PYTHONPATH=src WEALL_API="${API_URL}" WEALL_CHAIN_ID="${CHAIN_ID}" WEALL_ACCOUNT="${ACCOUNT}" WEALL_POST_BODY="${POST_BODY}" WEALL_MEDIA_TEXT="${MEDIA_TEXT}" python scripts/golden_path_full_stack.py

deactivate

cat <<MSG

Browser verification:
  1. Open ${FEED_URL}
  2. Refresh the feed/home view once
  3. Look for account: ${ACCOUNT}
  4. Look for post body: ${POST_BODY}
  5. Demo summary JSON: ${ROOT_DIR}/generated/demo_bootstrap_result.json
MSG
