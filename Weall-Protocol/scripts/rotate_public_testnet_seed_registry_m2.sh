#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH:-${ROOT}/configs/public_testnet_seed_registry.json}"
TRUST_ROOTS="${WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH:-${ROOT}/configs/public_testnet_trust_roots.json}"
SIGNER="${ROOT}/scripts/sign_public_seed_registry_v1_5.py"

: "${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY:?Set WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY in the current shell; never place it in a file or shell history.}"

TMP="$(mktemp "${REGISTRY}.signed.XXXXXX")"
trap 'rm -f "${TMP}"' EXIT

PYTHONPATH="${ROOT}/src" \
WEALL_MODE=prod \
WEALL_PUBLIC_TESTNET=1 \
WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH="${TRUST_ROOTS}" \
python3 "${SIGNER}" \
  --input "${REGISTRY}" \
  --output "${TMP}" \
  --signature-profile pq-mldsa-v1

mv "${TMP}" "${REGISTRY}"
trap - EXIT

PYTHONPATH="${ROOT}/src" \
WEALL_MODE=prod \
WEALL_PUBLIC_TESTNET=1 \
WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH="${TRUST_ROOTS}" \
WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH="${REGISTRY}" \
python3 - <<'PY'
from weall.api.public_seed_registry import load_public_seed_registry
loaded = load_public_seed_registry(allow_local=False)
status = loaded.get("seed_registry_signature_status") or {}
if status.get("verified") is not True or status.get("trust") != "pinned":
    raise SystemExit(f"seed_registry_not_pinned:{status}")
print("OK: public-testnet seed registry re-signed and pinned")
PY
