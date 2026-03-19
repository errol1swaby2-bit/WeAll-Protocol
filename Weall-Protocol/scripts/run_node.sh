#!/usr/bin/env sh
set -eu

# WeAll node launcher that supports Docker secrets / file-based keys.
# Goal: avoid putting private keys directly into docker-compose env blocks.

read_secret_file() {
  p="$1"
  if [ -z "${p:-}" ]; then
    return 1
  fi
  if [ ! -f "$p" ]; then
    return 1
  fi
  # Trim whitespace/newlines
  tr -d '\r' < "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

maybe_export_from_file() {
  var="$1"
  file_var="$2"

  # If env already provided, keep it.
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
    # shellcheck disable=SC2163
    export "$var=$val"
  fi
}

# Load from explicit *_FILE env vars (recommended)
maybe_export_from_file "WEALL_NODE_PRIVKEY" "WEALL_NODE_PRIVKEY_FILE"
maybe_export_from_file "WEALL_NODE_PUBKEY"  "WEALL_NODE_PUBKEY_FILE"
maybe_export_from_file "WEALL_VALIDATOR_ACCOUNT" "WEALL_VALIDATOR_ACCOUNT_FILE"

# Convenience: support standard Docker secrets file names if *_FILE not set
# (You can still override by setting the *_FILE env vars.)
if [ -z "${WEALL_NODE_PRIVKEY:-}" ] && [ -f "/run/secrets/weall_node_privkey" ]; then
  export WEALL_NODE_PRIVKEY="$(read_secret_file /run/secrets/weall_node_privkey || true)"
fi
if [ -z "${WEALL_NODE_PUBKEY:-}" ] && [ -f "/run/secrets/weall_node_pubkey" ]; then
  export WEALL_NODE_PUBKEY="$(read_secret_file /run/secrets/weall_node_pubkey || true)"
fi
if [ -z "${WEALL_VALIDATOR_ACCOUNT:-}" ] && [ -f "/run/secrets/weall_validator_account" ]; then
  export WEALL_VALIDATOR_ACCOUNT="$(read_secret_file /run/secrets/weall_validator_account || true)"
fi

# If networking/BFT is enabled, fail-closed if identity keys are missing
WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-0}"
WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"

if [ "$WEALL_NET_ENABLED" = "1" ] || [ "$WEALL_BFT_ENABLED" = "1" ]; then
  if [ -z "${WEALL_NODE_PUBKEY:-}" ] || [ -z "${WEALL_NODE_PRIVKEY:-}" ]; then
    echo "ERROR: networking/BFT enabled but node identity keys are missing." >&2
    echo "  Provide WEALL_NODE_PUBKEY/WEALL_NODE_PRIVKEY OR mount secrets and set:" >&2
    echo "    WEALL_NODE_PUBKEY_FILE=/run/secrets/weall_node_pubkey" >&2
    echo "    WEALL_NODE_PRIVKEY_FILE=/run/secrets/weall_node_privkey" >&2
    exit 2
  fi
fi

if [ "$WEALL_BFT_ENABLED" = "1" ] && [ "$WEALL_BLOCK_LOOP_AUTOSTART" = "1" ]; then
  echo "ERROR: cannot combine WEALL_BFT_ENABLED=1 with WEALL_BLOCK_LOOP_AUTOSTART=1." >&2
  exit 2
fi

if [ "$WEALL_BFT_ENABLED" = "1" ] || [ "$WEALL_BLOCK_LOOP_AUTOSTART" = "1" ] || [ "$WEALL_NET_LOOP_AUTOSTART" = "1" ]; then
  export GUNICORN_WORKERS="${GUNICORN_WORKERS:-1}"
else
  export GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"
fi


manifest_required_raw="${WEALL_REQUIRE_SIGNED_BOOTSTRAP_MANIFEST:-}"
manifest_required="0"
case "$(printf "%s" "$manifest_required_raw" | tr '[:upper:]' '[:lower:]')" in
  1|true|yes|y|on) manifest_required="1" ;;
  *) manifest_required="0" ;;
esac

if [ "$manifest_required" = "1" ] || [ -n "${WEALL_RELEASE_MANIFEST_PATH:-}" ] || [ -n "${WEALL_RELEASE_PUBKEY:-}" ] || [ -n "${WEALL_RELEASE_PUBKEY_FILE:-}" ]; then
  echo "[bootstrap-verify] verifying local signed release manifest posture" >&2
  set -- python3 scripts/verify_validator_bootstrap.py
  if [ -n "${WEALL_RELEASE_MANIFEST_PATH:-}" ]; then
    set -- "$@" --bundle "$WEALL_RELEASE_MANIFEST_PATH"
  fi
  if [ -n "${WEALL_RELEASE_PUBKEY:-}" ]; then
    set -- "$@" --release-pubkey "$WEALL_RELEASE_PUBKEY"
  fi
  PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}src" "$@" >/tmp/weall_bootstrap_verify.log 2>&1 || {
    cat /tmp/weall_bootstrap_verify.log >&2 || true
    echo "ERROR: signed release manifest verification failed." >&2
    exit 2
  }
fi

# Run the same production command as Dockerfile default CMD
exec sh -c "gunicorn weall.api.app:app \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --workers ${GUNICORN_WORKERS} \
  --timeout ${GUNICORN_TIMEOUT:-60} \
  --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} \
  --keep-alive ${GUNICORN_KEEPALIVE:-5} \
  --access-logfile - \
  --error-logfile -"
