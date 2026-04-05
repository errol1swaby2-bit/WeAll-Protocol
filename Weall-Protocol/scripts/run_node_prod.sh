#!/usr/bin/env sh
set -eu

export WEALL_MODE=prod

if [ -z "${WEALL_CHAIN_ID:-}" ]; then
  echo "ERROR: WEALL_CHAIN_ID must be set before running run_node_prod.sh" >&2
  exit 2
fi

if [ -z "${WEALL_CORS_ORIGINS:-}" ]; then
  echo "ERROR: WEALL_CORS_ORIGINS must be set explicitly before running run_node_prod.sh" >&2
  exit 2
fi

if [ -z "${WEALL_NODE_PRIVKEY_FILE:-${WEALL_NODE_PRIVKEY:-}}" ]; then
  echo "ERROR: node private key is required (WEALL_NODE_PRIVKEY_FILE or WEALL_NODE_PRIVKEY)" >&2
  exit 2
fi

if [ -z "${WEALL_NODE_PUBKEY_FILE:-${WEALL_NODE_PUBKEY:-}}" ]; then
  echo "ERROR: node public key is required (WEALL_NODE_PUBKEY_FILE or WEALL_NODE_PUBKEY)" >&2
  exit 2
fi

if [ -z "${WEALL_POH_EMAIL_SECRET_FILE:-${WEALL_POH_EMAIL_SECRET:-}}" ]; then
  echo "ERROR: WEALL_POH_EMAIL_SECRET_FILE or WEALL_POH_EMAIL_SECRET is required in production" >&2
  exit 2
fi

exec "$(dirname "$0")/run_node.sh"
