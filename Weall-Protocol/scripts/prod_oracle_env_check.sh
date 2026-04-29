#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
STRICT="${WEALL_ORACLE_ENV_STRICT:-0}"

fail() { echo "ERROR: $*" >&2; exit 2; }

read_secret_or_file() {
  local name="$1"
  local file_name="${name}_FILE"
  if [ -n "${!name:-}" ]; then
    printf '%s' "${!name}"
    return 0
  fi
  if [ -n "${!file_name:-}" ] && [ -f "${!file_name}" ]; then
    cat "${!file_name}"
    return 0
  fi
  return 1
}

# Keep these named guards explicit for production review/tests. Non-strict mode
# emits JSON diagnostics without requiring operator secrets, so static config and
# release audits can run in clean environments.
secret_must_not_be_plain_var() {
  local name="$1"
  if [ -n "${!name:-}" ]; then
    fail "secret_must_not_be_plain_var:${name}"
  fi
}

production_var_mismatch() {
  local name="$1"
  local expected="$2"
  local actual="${!name:-}"
  if [ -n "${actual}" ] && [ "${actual}" != "${expected}" ]; then
    fail "production_var_mismatch:${name}:expected=${expected}:actual=${actual}"
  fi
}

if [ ! -f "${MANIFEST}" ]; then
  fail "chain manifest not found: ${MANIFEST}"
fi

if [ "${STRICT}" = "1" ]; then
  [ -n "${WEALL_EMAIL_TRANSPORT:-}" ] || fail "WEALL_EMAIL_TRANSPORT must be set"
  [ -n "${WEALL_EMAIL_ORACLE_ID:-}" ] || fail "WEALL_EMAIL_ORACLE_ID must be set"
  read_secret_or_file WEALL_EMAIL_ORACLE_PRIVATE_KEY >/dev/null || fail "WEALL_EMAIL_ORACLE_PRIVATE_KEY or WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE must be set"
  secret_must_not_be_plain_var WEALL_SMTP_PASSWORD
  secret_must_not_be_plain_var WEALL_EMAIL_PASS
  production_var_mismatch WEALL_CHAIN_ID "weall-prod"
  production_var_mismatch WEALL_EXPECTED_CHAIN_ID "weall-prod"
  case "${WEALL_EMAIL_TRANSPORT}" in
    mock|dev_mock)
      fail "mock transport is not allowed for strict production oracle service"
      ;;
    stalwart_smtp|external_smtp|smtp)
      [ -n "${WEALL_SMTP_HOST:-${WEALL_EMAIL_HOST:-}}" ] || fail "SMTP host missing"
      [ -n "${WEALL_SMTP_PORT:-${WEALL_EMAIL_PORT:-587}}" ] || fail "SMTP port missing"
      [ -n "${WEALL_SMTP_FROM:-${WEALL_EMAIL_FROM:-}}" ] || fail "SMTP sender missing"
      [ -n "${WEALL_SMTP_USERNAME:-${WEALL_EMAIL_USER:-}}" ] || fail "SMTP username missing"
      read_secret_or_file WEALL_SMTP_PASSWORD >/dev/null || read_secret_or_file WEALL_EMAIL_PASS >/dev/null || fail "SMTP password file missing"
      ;;
    *) fail "unsupported WEALL_EMAIL_TRANSPORT=${WEALL_EMAIL_TRANSPORT}" ;;
  esac
fi

python3 -S - "${MANIFEST}" "${STRICT}" <<'PY'
import json
import os
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
strict = sys.argv[2] == "1"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
warnings = []
errors = []

for key in ("chain_id", "genesis_hash", "genesis_state_root", "tx_index_hash"):
    value = str(manifest.get(key) or "").strip()
    if not value or value.lower().startswith("replace"):
        errors.append(f"manifest_{key}_not_pinned")

trusted = manifest.get("trusted_authority_pubkeys") or []
if (not trusted) or any(str(x).lower().startswith("replace") for x in trusted):
    warnings.append("trusted_authority_pubkeys_still_placeholder")

if not os.environ.get("WEALL_EMAIL_TRANSPORT"):
    warnings.append("WEALL_EMAIL_TRANSPORT_missing_non_strict_static_check")
if not os.environ.get("WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE") and not os.environ.get("WEALL_EMAIL_ORACLE_PRIVATE_KEY"):
    warnings.append("WEALL_EMAIL_ORACLE_PRIVATE_KEY_missing_non_strict_static_check")
if os.environ.get("WEALL_TRUSTED_AUTHORITY_PUBKEYS"):
    warnings.append("WEALL_TRUSTED_AUTHORITY_PUBKEYS_env_override_present")

if strict and errors:
    print(json.dumps({"ok": False, "errors": errors, "warnings": warnings}, indent=2, sort_keys=True))
    sys.exit(2)

print(json.dumps({
    "ok": not bool(errors),
    "strict": strict,
    "manifest": str(manifest_path),
    "chain_id": manifest.get("chain_id"),
    "genesis_hash": manifest.get("genesis_hash"),
    "genesis_state_root": manifest.get("genesis_state_root"),
    "tx_index_hash": manifest.get("tx_index_hash"),
    "expected_profile": (manifest.get("oracle") or {}).get("expected_profile"),
    "transport": os.environ.get("WEALL_EMAIL_TRANSPORT", ""),
    "warnings": warnings,
    "errors": errors,
}, indent=2, sort_keys=True))
PY
