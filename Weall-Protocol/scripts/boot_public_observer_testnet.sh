#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY_PATH="${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH:-}"
if [[ -z "$REGISTRY_PATH" ]]; then
  for candidate in \
    "$ROOT/public_testnet_seed_registry.json" \
    "$ROOT/config/public_testnet_seed_registry.json" \
    "$ROOT/configs/public_testnet_seed_registry.json" \
    "$(dirname "$ROOT")/public_testnet_seed_registry.json" \
    "$(dirname "$ROOT")/Weall-Protocol/config/public_testnet_seed_registry.json" \
    "$(dirname "$ROOT")/Weall-Protocol/configs/public_testnet_seed_registry.json"; do
    if [[ -f "$candidate" ]]; then
      REGISTRY_PATH="$candidate"
      break
    fi
  done
fi

if [[ -z "$REGISTRY_PATH" || ! -f "$REGISTRY_PATH" ]]; then
  cat >&2 <<'EOF'
ERROR: no public_testnet_seed_registry.json found.

Place the signed launch registry at one of the default paths, for example:
  Weall-Protocol/configs/public_testnet_seed_registry.json
or set:
  WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH=/absolute/path/to/public_testnet_seed_registry.json
EOF
  exit 2
fi

if [[ -z "${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY:-}${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEYS:-}" ]]; then
  cat >&2 <<'EOF'
ERROR: public registry signer pin is required.
Set WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY or WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEYS before boot.
EOF
  exit 2
fi

export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_API_MODE="${WEALL_API_MODE:-node}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"
export WEALL_OBSERVER_EDGE_MODE="${WEALL_OBSERVER_EDGE_MODE:-1}"
export WEALL_PUBLIC_TESTNET="${WEALL_PUBLIC_TESTNET:-1}"
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH="$REGISTRY_PATH"

python - <<'PY'
from weall.api.public_seed_registry import load_public_seed_registry
registry = load_public_seed_registry()
status = registry.get("seed_registry_signature_status", {})
if status.get("verified") is not True:
    raise SystemExit("public seed registry signature is not verified")
if registry.get("resettable_testnet") is not True or registry.get("economics_active") is not False:
    raise SystemExit("public seed registry must be resettable and non-economic")
print("OK: signed public seed registry verified")
print(f"chain_id={registry.get('chain_id')}")
print(f"genesis_hash={registry.get('genesis_hash')}")
print(f"seed_api_urls={len(registry.get('seed_api_urls') or [])}")
print(f"seed_p2p_urls={len(registry.get('seed_p2p_urls') or [])}")
print(f"validator_endpoint_hints={len(registry.get('validator_endpoints') or [])}")
PY

cat <<EOF
Starting WeAll public observer node...
Backend: http://127.0.0.1:${WEALL_API_PORT:-8000}
After boot, check:
  curl -s http://127.0.0.1:${WEALL_API_PORT:-8000}/v1/nodes/seeds | python -m json.tool
  curl -s http://127.0.0.1:${WEALL_API_PORT:-8000}/v1/nodes/validators | python -m json.tool
  curl -s http://127.0.0.1:${WEALL_API_PORT:-8000}/v1/observer/edge/status | python -m json.tool
EOF

exec python -m weall.api
