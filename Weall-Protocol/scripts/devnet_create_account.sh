#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"
ACCOUNT="${WEALL_ACCOUNT:-}"

cd "${REPO_ROOT}"
# Generate independent recovery and ML-KEM evidence authorities before account
# registration.  Private material stays in the operator-only keyfile.
if [[ ! -d "${REPO_ROOT}/../web/node_modules" ]]; then
  echo "ERROR: web dependencies are required to generate ML-KEM actor keys. Run: cd ${REPO_ROOT}/../web && npm ci" >&2
  exit 2
fi
ENSURE_ARGS=(--api "${API}" ensure-keyfile --keyfile "${KEYFILE}")
if [[ -n "${ACCOUNT}" ]]; then
  ENSURE_ARGS+=(--account "${ACCOUNT}")
fi
case "${WEALL_DEVNET_FRESH_ACCOUNT:-1}" in
  0|false|FALSE|no|NO|off|OFF) ;;
  *) ENSURE_ARGS+=(--fresh) ;;
esac
python3 scripts/devnet_tx.py "${ENSURE_ARGS[@]}" >/dev/null

# Generate the independent recovery and evidence-encryption authorities only
# after the active account key is final.  The registration command must reuse
# this prepared keyfile; otherwise its default fresh-key behavior would discard
# the newly generated authorities before constructing ACCOUNT_REGISTER.
node "${REPO_ROOT}/../web/scripts/generate_m2_actor_keys.mjs" "${KEYFILE}" >/dev/null
ARGS=(--api "${API}" create-account --keyfile "${KEYFILE}" --reuse-keyfile)
if [[ -n "${ACCOUNT}" ]]; then
  ARGS+=(--account "${ACCOUNT}")
fi
RESULT_FILE="$(mktemp "${TMPDIR:-/tmp}/weall_devnet_create_account_XXXXXX.json")"
trap 'rm -f "${RESULT_FILE}"' EXIT
python3 scripts/devnet_tx.py "${ARGS[@]}" "$@" > "${RESULT_FILE}"

# When confirmation was requested, fail closed unless the canonical account
# record contains the exact independent authorities prepared above.
python3 - "${KEYFILE}" "${RESULT_FILE}" <<'PY_VERIFY_AUTHORITIES'
import json, sys
keyfile_path, result_path = sys.argv[1], sys.argv[2]
with open(keyfile_path, 'r', encoding='utf-8') as f:
    keydata = json.load(f)
with open(result_path, 'r', encoding='utf-8') as f:
    result = json.load(f)
state = result.get('account_state')
if not isinstance(state, dict):
    raise SystemExit(0)
expected_kem = str(keydata.get('evidence_kem_public_key_b64') or '').strip()
actual_kem = str(((state.get('evidence_encryption') or {}).get('public_key')) or '').strip()
if not expected_kem or actual_kem != expected_kem:
    raise SystemExit('account_register_evidence_kem_postcondition_failed')
expected_recovery = str(keydata.get('recovery_public_key_hex') or '').strip()
actual_recovery = str((((state.get('recovery') or {}).get('offline_key') or {}).get('pubkey')) or '').strip()
if not expected_recovery or actual_recovery != expected_recovery:
    raise SystemExit('account_register_recovery_key_postcondition_failed')
PY_VERIFY_AUTHORITIES
cat "${RESULT_FILE}"
