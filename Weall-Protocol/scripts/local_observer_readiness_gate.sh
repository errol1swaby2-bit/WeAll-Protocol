#!/usr/bin/env bash
set -euo pipefail

# Local-only gate for everything that can be verified before a real second-machine
# observer rehearsal. This does not claim that the two-machine test happened.
# It proves the production manifest is pinned, a public observer bundle can be
# generated and verified, observer-mode preflight forces non-authority posture,
# and no genesis/operator private material is required by the observer path.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-$ROOT_DIR/configs/chains/weall-genesis.json}"
AUTHORITY_URL="${WEALL_LOCAL_OBSERVER_AUTHORITY_URL:-https://observer-gate.invalid}"
TMP_DIR="${WEALL_LOCAL_OBSERVER_GATE_DIR:-}"
KEEP_TMP="${WEALL_LOCAL_OBSERVER_KEEP_TMP:-0}"

if [[ -z "$TMP_DIR" ]]; then
  TMP_DIR="$(mktemp -d /tmp/weall-local-observer-gate.XXXXXX)"
  CLEAN_TMP=1
else
  mkdir -p "$TMP_DIR"
  CLEAN_TMP=0
fi

cleanup() {
  if [[ "${CLEAN_TMP:-0}" == "1" && "$KEEP_TMP" != "1" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

fail() {
  echo "[local-observer-gate:FAIL] $*" >&2
  exit 1
}

[[ -f "$MANIFEST_PATH" ]] || fail "manifest not found: $MANIFEST_PATH"
[[ "$AUTHORITY_URL" == https://* ]] || fail "WEALL_LOCAL_OBSERVER_AUTHORITY_URL must be https://..."

# Observer rehearsal must not depend on authority, validator, oracle, message-transport, or
# Cloudflare secrets being present in the operator shell.
for var in \
  WEALL_AUTHORITY_SIGNER_PRIVKEY \
  WEALL_AUTHORITY_PRIVKEY \
  WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY \
  WEALL_ORACLE_AUTHORITY_PRIVKEY \
  WEALL_CLOUDFLARE_API_TOKEN \
  WEALL_NODE_PRIVKEY \
  WEALL_VALIDATOR_ACCOUNT; do
  if [[ -n "${!var:-}" ]]; then
    fail "$var must not be set for the local observer readiness gate"
  fi
done

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

python3 -S scripts/check_tx_canon_artifacts.py >/tmp/weall-local-observer-gate-tx-canon.out
bash scripts/prod_chain_manifest_check.sh "$MANIFEST_PATH" >/tmp/weall-local-observer-gate-manifest.out

BUNDLE_PATH="$TMP_DIR/external-observer-bundle.json"
python3 scripts/build_external_observer_bundle.py \
  --manifest "$MANIFEST_PATH" \
  --out "$BUNDLE_PATH" \
  --authority-url "$AUTHORITY_URL" \
  --generated-at-ms 0 >/tmp/weall-local-observer-gate-bundle-path.out

python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle "$BUNDLE_PATH" \
  --manifest "$MANIFEST_PATH" \
  --json >/tmp/weall-local-observer-gate-bundle-check.json

# The smoke script verifies bundle safety, manifest pinning, observer-only mode,
# disabled signing/BFT/helper authority, and absence of external identity-provider
# or authority-signer secrets. No remote genesis API is contacted here because
# this gate is explicitly local-only.
env -u WEALL_GENESIS_API_BASE -u WEALL_API_BASE -u WEALL_NET_RELAY_URLS \
  bash scripts/external_observer_onboarding_smoke.sh "$BUNDLE_PATH" >/tmp/weall-local-observer-gate-smoke.out

python3 - "$BUNDLE_PATH" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

bundle = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
text = json.dumps(bundle, sort_keys=True)
forbidden_values = [
    "WEALL_AUTHORITY_SIGNER_PRIVKEY",
    "WEALL_AUTHORITY_PRIVKEY",
    "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
    "WEALL_ORACLE_AUTHORITY_PRIVKEY",
    "WEALL_CLOUDFLARE_API_TOKEN",
]
# These names are allowed inside the public secret_boundary documentation but
# no actual private key material, seed, token, password, or local file path may
# appear outside that section.
actual_secret_pattern = re.compile(r"(privkey|private[_-]?key|seed|password|token)\s*[:=]\s*[0-9a-fA-F]{16,}", re.I)
if actual_secret_pattern.search(text):
    raise SystemExit("bundle_contains_actual_secret_like_material")
observer = bundle.get("observer") if isinstance(bundle.get("observer"), dict) else {}
if observer.get("validator_signing_enabled") is not False:
    raise SystemExit("observer_validator_signing_not_disabled")
if observer.get("bft_enabled") is not False:
    raise SystemExit("observer_bft_not_disabled")
if observer.get("helper_authority_enabled") is not False:
    raise SystemExit("observer_helper_authority_not_disabled")
if observer.get("block_loop_autostart") is not False:
    raise SystemExit("observer_block_loop_not_disabled")
print("OK: local observer bundle is public-only and observer-safe")
PY

cat <<MSG
OK: local observer readiness gate passed
- tx canon synchronized
- production chain manifest pinned
- public observer bundle generated and verified
- observer preflight forces observer-only mode
- validator signing, BFT, helper authority, and block loop are disabled
- no authority, validator, Cloudflare, message-transport, or legacy oracle secret is required

This is not a substitute for scripts/rehearse_external_observer_two_machine.sh.
It is the local precondition that should pass before the real second-machine rehearsal.
MSG
