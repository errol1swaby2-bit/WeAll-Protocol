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

TRUST_ROOTS_PATH="${WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH:-}"
if [[ -z "$TRUST_ROOTS_PATH" ]]; then
  for candidate in \
    "$ROOT/public_testnet_trust_roots.json" \
    "$ROOT/config/public_testnet_trust_roots.json" \
    "$ROOT/configs/public_testnet_trust_roots.json" \
    "$(dirname "$ROOT")/public_testnet_trust_roots.json" \
    "$(dirname "$ROOT")/Weall-Protocol/config/public_testnet_trust_roots.json" \
    "$(dirname "$ROOT")/Weall-Protocol/configs/public_testnet_trust_roots.json"; do
    if [[ -f "$candidate" ]]; then
      TRUST_ROOTS_PATH="$candidate"
      break
    fi
  done
fi

if [[ -z "$REGISTRY_PATH" || ! -f "$REGISTRY_PATH" ]]; then
  if [[ -z "${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL:-}${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URLS:-}${WEALL_PUBLIC_SEED_REGISTRY_URL:-}${WEALL_PUBLIC_SEED_REGISTRY_URLS:-}" && -z "$TRUST_ROOTS_PATH" ]]; then
    cat >&2 <<'EOF'
ERROR: no public_testnet_seed_registry.json or pinned remote registry URL found.

Place the signed launch registry at one of the default paths, for example:
  Weall-Protocol/configs/public_testnet_seed_registry.json
or set:
  WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH=/absolute/path/to/public_testnet_seed_registry.json
or use the hybrid remote source path:
  WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL=https://example.org/public_testnet_seed_registry.json
or commit trust roots:
  Weall-Protocol/configs/public_testnet_trust_roots.json

Remote registries are accepted only after the same signature and pinned-signer checks as local files.
Signer pins may come from WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY, WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEYS, or configs/public_testnet_trust_roots.json.
EOF
    exit 2
  fi
fi

export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_API_MODE="${WEALL_API_MODE:-node}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"
export WEALL_OBSERVER_EDGE_MODE="${WEALL_OBSERVER_EDGE_MODE:-1}"
export WEALL_PUBLIC_TESTNET="${WEALL_PUBLIC_TESTNET:-1}"

TESTNET_MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-$ROOT/configs/chains/weall-testnet-v1.json}"
if [[ -f "$TESTNET_MANIFEST_PATH" ]]; then
  export WEALL_CHAIN_MANIFEST_PATH="$TESTNET_MANIFEST_PATH"
  eval "$(python3 - <<'PY'
import json
import os
import shlex
from pathlib import Path
manifest = json.loads(Path(os.environ['WEALL_CHAIN_MANIFEST_PATH']).read_text(encoding='utf-8'))
mapping = {
    'WEALL_CHAIN_ID': manifest.get('chain_id', ''),
    'WEALL_EXPECTED_CHAIN_ID': manifest.get('chain_id', ''),
    'WEALL_EXPECTED_GENESIS_HASH': manifest.get('genesis_hash', ''),
    'WEALL_EXPECTED_PROTOCOL_PROFILE_HASH': manifest.get('protocol_profile_hash', ''),
    'WEALL_EXPECTED_TX_INDEX_HASH': manifest.get('tx_index_hash', ''),
    'WEALL_PUBLIC_TESTNET_NETWORK_ID': manifest.get('network_id', 'weall-public-observer-testnet-v1'),
}
for key, value in mapping.items():
    if os.environ.get(key):
        continue
    print(f"export {key}={shlex.quote(str(value or ''))}")
PY
)"
fi
if [[ -n "$REGISTRY_PATH" ]]; then
  export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH="$REGISTRY_PATH"
else
  unset WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH
fi
if [[ -n "$TRUST_ROOTS_PATH" ]]; then
  export WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH="$TRUST_ROOTS_PATH"
fi

python3 - <<'PY'
from weall.api.public_seed_registry import PublicSeedRegistryError, load_public_seed_registry
try:
    registry = load_public_seed_registry()
except PublicSeedRegistryError as exc:
    raise SystemExit(f"public seed registry failed: {exc}") from exc
status = registry.get("seed_registry_signature_status", {})
if status.get("verified") is not True:
    raise SystemExit("public seed registry signature is not verified")
if registry.get("resettable_testnet") is not True or registry.get("economics_active") is not False:
    raise SystemExit("public seed registry must be resettable and non-economic")
print("OK: signed public seed registry verified")
print(f"registry_source_kind={registry.get('registry_source_kind')}")
print(f"registry_source={registry.get('registry_source')}")
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

exec python3 -m weall.api
