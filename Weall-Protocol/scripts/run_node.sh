#!/usr/bin/env sh
set -eu

read_secret_file() {
  p="$1"
  if [ -z "${p:-}" ] || [ ! -f "$p" ]; then
    return 1
  fi
  tr -d '\r' < "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

maybe_export_from_file() {
  var="$1"
  file_var="$2"
  eval "cur=\${$var:-}"
  if [ -n "${cur:-}" ]; then
    return 0
  fi
  eval "fp=\${$file_var:-}"
  if [ -z "${fp:-}" ]; then
    return 0
  fi
  val="$(read_secret_file "$fp" || true)"
  if [ -n "${val:-}" ]; then
    export "$var=$val"
  fi
}

die() {
  echo "ERROR: $*" >&2
  exit 2
}

env_is_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

require_nonempty() {
  var="$1"
  eval "val=\${$var:-}"
  if [ -z "${val:-}" ]; then
    die "required setting missing: $var"
  fi
}

maybe_export_from_file "WEALL_NODE_PRIVKEY" "WEALL_NODE_PRIVKEY_FILE"
maybe_export_from_file "WEALL_NODE_PUBKEY" "WEALL_NODE_PUBKEY_FILE"
maybe_export_from_file "WEALL_VALIDATOR_ACCOUNT" "WEALL_VALIDATOR_ACCOUNT_FILE"
maybe_export_from_file "WEALL_POH_EMAIL_SECRET" "WEALL_POH_EMAIL_SECRET_FILE"

if [ -z "${WEALL_NODE_PRIVKEY:-}" ] && [ -f "/run/secrets/weall_node_privkey" ]; then
  export WEALL_NODE_PRIVKEY="$(read_secret_file /run/secrets/weall_node_privkey || true)"
fi
if [ -z "${WEALL_NODE_PUBKEY:-}" ] && [ -f "/run/secrets/weall_node_pubkey" ]; then
  export WEALL_NODE_PUBKEY="$(read_secret_file /run/secrets/weall_node_pubkey || true)"
fi
if [ -z "${WEALL_VALIDATOR_ACCOUNT:-}" ] && [ -f "/run/secrets/weall_validator_account" ]; then
  export WEALL_VALIDATOR_ACCOUNT="$(read_secret_file /run/secrets/weall_validator_account || true)"
fi
if [ -z "${WEALL_POH_EMAIL_SECRET:-}" ] && [ -f "/run/secrets/weall_poh_email_secret" ]; then
  export WEALL_POH_EMAIL_SECRET="$(read_secret_file /run/secrets/weall_poh_email_secret || true)"
fi

if [ -z "${WEALL_MODE:-}" ]; then
  die "WEALL_MODE must be set explicitly (allowed: prod, dev, test)"
fi

case "${WEALL_MODE}" in
  prod|dev|test) ;;
  *) die "invalid WEALL_MODE='${WEALL_MODE}'. Allowed: prod, dev, test" ;;
esac

export WEALL_MODE

WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-0}"
WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"
WEALL_GENESIS_MODE="${WEALL_GENESIS_MODE:-0}"
export WEALL_GENESIS_MODE

if [ "${WEALL_MODE}" = "prod" ]; then
  if env_is_true "${WEALL_GENESIS_MODE}"; then die "WEALL_GENESIS_MODE is forbidden in production"; fi
  if env_is_true "${WEALL_BLOCK_LOOP_ENABLED:-0}"; then die "WEALL_BLOCK_LOOP_ENABLED is forbidden in production"; fi
  if env_is_true "${WEALL_PRODUCE_EMPTY_BLOCKS:-0}"; then die "WEALL_PRODUCE_EMPTY_BLOCKS is forbidden in production"; fi
  if [ -n "${WEALL_BLOCK_INTERVAL_MS:-}" ]; then die "WEALL_BLOCK_INTERVAL_MS is forbidden in production"; fi
  if [ "${WEALL_SIGVERIFY:-1}" = "0" ]; then die "WEALL_SIGVERIFY=0 is forbidden in production"; fi
  if env_is_true "${WEALL_AUTOVOTE:-0}"; then die "WEALL_AUTOVOTE is forbidden in production"; fi
  if env_is_true "${WEALL_AUTOTIMEOUT:-0}"; then die "WEALL_AUTOTIMEOUT is forbidden in production"; fi
  if env_is_true "${WEALL_BFT_ALLOW_QC_LESS_BLOCKS:-0}"; then die "WEALL_BFT_ALLOW_QC_LESS_BLOCKS is forbidden in production"; fi
  if env_is_true "${WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS:-0}"; then die "WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS is forbidden in production"; fi
  if env_is_true "${WEALL_UNSAFE_DEV:-0}"; then die "WEALL_UNSAFE_DEV is forbidden in production"; fi
  if [ -z "${WEALL_CORS_ORIGINS:-}" ]; then die "WEALL_CORS_ORIGINS must be set explicitly in production"; fi
else
  if [ -z "${WEALL_CORS_ORIGINS:-}" ]; then
    export WEALL_CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173"
  fi
fi

if env_is_true "${WEALL_NET_ENABLED}" || env_is_true "${WEALL_BFT_ENABLED}" || env_is_true "${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"; then
  require_nonempty "WEALL_NODE_PUBKEY"
  require_nonempty "WEALL_NODE_PRIVKEY"
fi

if env_is_true "${WEALL_BFT_ENABLED}"; then
  require_nonempty "WEALL_VALIDATOR_ACCOUNT"
fi

if env_is_true "${WEALL_BFT_ENABLED}" && env_is_true "${WEALL_BLOCK_LOOP_AUTOSTART}"; then
  die "cannot combine WEALL_BFT_ENABLED=1 with WEALL_BLOCK_LOOP_AUTOSTART=1"
fi

if [ "${WEALL_MODE}" = "prod" ]; then
  if [ -z "${WEALL_CHAIN_ID:-}" ]; then die "WEALL_CHAIN_ID must be set in production"; fi
  if [ -z "${WEALL_POH_EMAIL_SECRET:-}" ]; then
    die "WEALL_POH_EMAIL_SECRET (or WEALL_POH_EMAIL_SECRET_FILE) must be set in production"
  fi
fi

GUNICORN_BIND="${GUNICORN_BIND:-0.0.0.0:8000}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-1}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-120}"
GUNICORN_LOG_LEVEL="${GUNICORN_LOG_LEVEL:-info}"

exec gunicorn weall.api.app:app \
  -k uvicorn.workers.UvicornWorker \
  --bind "${GUNICORN_BIND}" \
  --workers "${GUNICORN_WORKERS}" \
  --timeout "${GUNICORN_TIMEOUT}" \
  --log-level "${GUNICORN_LOG_LEVEL}" \
  --access-logfile - \
  --error-logfile -
