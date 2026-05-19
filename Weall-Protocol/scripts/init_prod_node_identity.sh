#!/usr/bin/env bash
set -euo pipefail

# Initialize a production-style node identity once, then print the env exports
# expected by scripts/run_node_prod.sh. This script deliberately refuses partial
# or overwritten identities so normal boot never silently rotates node identity.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PRIV_PATH="${WEALL_NODE_PRIVKEY_FILE:-${REPO_ROOT}/secrets/weall_node_privkey}"
PUB_PATH="${WEALL_NODE_PUBKEY_FILE:-${REPO_ROOT}/secrets/weall_node_pubkey}"
GENERATOR="${REPO_ROOT}/scripts/genesis_generate_node_key.py"

usage() {
  cat <<'EOF'
Usage: bash scripts/init_prod_node_identity.sh [--emit-shell-env]

Creates secrets/weall_node_privkey and secrets/weall_node_pubkey only when both
are missing. If both already exist, it reuses them. If exactly one exists, it
fails closed rather than inventing a mismatched identity.

To persist exports in your current shell:
  eval "$(bash scripts/init_prod_node_identity.sh --emit-shell-env)"
EOF
}

EMIT_SHELL_ENV=0
case "${1:-}" in
  "") ;;
  --emit-shell-env) EMIT_SHELL_ENV=1 ;;
  -h|--help) usage; exit 0 ;;
  *) echo "ERROR: unknown argument: ${1}" >&2; usage >&2; exit 2 ;;
esac

if [[ -e "${PRIV_PATH}" && ! -e "${PUB_PATH}" ]]; then
  echo "ERROR: node private key exists but public key is missing: ${PUB_PATH}" >&2
  exit 2
fi

if [[ ! -e "${PRIV_PATH}" && -e "${PUB_PATH}" ]]; then
  echo "ERROR: node public key exists but private key is missing: ${PRIV_PATH}" >&2
  exit 2
fi

if [[ ! -e "${PRIV_PATH}" && ! -e "${PUB_PATH}" ]]; then
  if [[ "${PRIV_PATH}" != "${REPO_ROOT}/secrets/weall_node_privkey" || "${PUB_PATH}" != "${REPO_ROOT}/secrets/weall_node_pubkey" ]]; then
    echo "ERROR: custom key paths are set but files do not exist." >&2
    echo "Create the custom keypair explicitly, or unset WEALL_NODE_PRIVKEY_FILE/WEALL_NODE_PUBKEY_FILE and rerun." >&2
    exit 2
  fi
  python3 "${GENERATOR}" >/dev/null
fi

if [[ ! -s "${PRIV_PATH}" ]]; then
  echo "ERROR: node private key file is empty: ${PRIV_PATH}" >&2
  exit 2
fi

if [[ ! -s "${PUB_PATH}" ]]; then
  echo "ERROR: node public key file is empty: ${PUB_PATH}" >&2
  exit 2
fi

chmod 600 "${PRIV_PATH}" 2>/dev/null || true
chmod 644 "${PUB_PATH}" 2>/dev/null || true

if [[ "${EMIT_SHELL_ENV}" == "1" ]]; then
  printf 'export WEALL_NODE_PRIVKEY_FILE=%q\n' "${PRIV_PATH}"
  printf 'export WEALL_NODE_PUBKEY_FILE=%q\n' "${PUB_PATH}"
else
  echo "Production node identity ready."
  echo "Private key file: ${PRIV_PATH}"
  echo "Public key file:  ${PUB_PATH}"
  echo
  echo "Run this to export for the current shell:"
  echo "  eval \"\$(bash scripts/init_prod_node_identity.sh --emit-shell-env)\""
fi
