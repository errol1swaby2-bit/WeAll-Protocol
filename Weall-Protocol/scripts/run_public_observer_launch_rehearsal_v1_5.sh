#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_public_observer_launch_rehearsal_v1_5.sh --api-base <url> [--registry <path>] [--out <path>]

Runs the public-observer launch transcript collector against a live signed seed or
Genesis API. This is a runtime evidence command; its output should be attached
with release evidence after a real public registry is published.
EOF
}

API_BASE=""
REGISTRY=""
OUT="generated/public_observer_launch_runtime_transcript_v1_5.json"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    --registry) REGISTRY="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$API_BASE" ]]; then
  echo "missing --api-base" >&2
  usage >&2
  exit 2
fi

cd "$(dirname "$0")/.."
export WEALL_PUBLIC_TESTNET="${WEALL_PUBLIC_TESTNET:-1}"
if [[ -n "$REGISTRY" ]]; then
  export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH="$REGISTRY"
fi

if [[ -z "${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY:-}" ]]; then
  echo "missing WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY" >&2
  exit 2
fi

CMD=(python scripts/gen_public_observer_launch_transcript_v1_5.py --runtime-json --api-base "$API_BASE" --out "$OUT")
if [[ -n "$REGISTRY" ]]; then
  CMD+=(--registry "$REGISTRY")
fi
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" "${CMD[@]}"
