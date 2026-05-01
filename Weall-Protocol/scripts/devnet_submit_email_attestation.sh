#!/usr/bin/env bash
set -euo pipefail

# Submit Tier-1 PoH email verification through the provider-neutral
# email_control_attestation_v1 path. This uses normal public API routes only:
# begin challenge -> complete challenge -> submit POH_EMAIL_ATTESTATION_SUBMIT.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"
ACCOUNT="${WEALL_ACCOUNT:-}"
EMAIL="${WEALL_EMAIL:-devnet-human@example.org}"
CODE="${WEALL_EMAIL_CODE:-}"

cd "${REPO_ROOT}"

if [ -z "${ACCOUNT}" ]; then
  echo "WEALL_ACCOUNT is required" >&2
  exit 2
fi

ARGS=(
  python3 scripts/devnet_tx.py
  --api "${API}"
  email-tier1
  --account "${ACCOUNT}"
  --keyfile "${KEYFILE}"
  --email "${EMAIL}"
)

if [ -n "${CODE}" ]; then
  ARGS+=(--code "${CODE}")
fi

exec "${ARGS[@]}"
