#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/capture_public_observer_open_download_transcript_v1_5.sh \
    --api-base <seed-or-genesis-api-url> \
    --registry <path-to-signed-registry> \
    --out-dir <evidence-dir> \
    [--frontend-url <url>]

Captures the external public-observer open-download transcript package for
AUD-628-P1-001. This script records evidence only. It does not close the blocker,
grant authority, enable validator signing, activate economics, or claim public beta
readiness.

Required environment:
  WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published registry signer public key>

The resulting directory is intentionally untracked runtime evidence unless a real
external transcript is attached and reviewed separately.
USAGE
}

API_BASE=""
REGISTRY=""
OUT_DIR=""
FRONTEND_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    --registry) REGISTRY="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --frontend-url) FRONTEND_URL="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$API_BASE" || -z "$REGISTRY" || -z "$OUT_DIR" ]]; then
  echo "missing required --api-base, --registry, or --out-dir" >&2
  usage >&2
  exit 2
fi

if [[ -z "${WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY:-}" ]]; then
  echo "missing WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_ABS="$(python - "$OUT_DIR" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
mkdir -p "$OUT_ABS/api" "$OUT_ABS/frontend" "$OUT_ABS/logs"

cd "$ROOT"
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH="$REGISTRY"

{
  echo "weall public observer open-download transcript"
  echo "schema=weall.v1_5.public_observer_open_download_transcript_package"
  echo "blocker=AUD-628-P1-001"
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root=$ROOT"
  echo "git_head=$(git rev-parse HEAD 2>/dev/null || true)"
  echo "git_branch=$(git branch --show-current 2>/dev/null || true)"
  echo "git_status_short_begin"
  git status --short --untracked-files=all 2>/dev/null || true
  echo "git_status_short_end"
  echo "python=$(python --version 2>&1)"
  echo "api_base=$API_BASE"
  echo "registry=$REGISTRY"
  echo "registry_sha256=$(python - "$REGISTRY" <<'PY'
from pathlib import Path
import hashlib, sys
p = Path(sys.argv[1])
print(hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "missing")
PY
)"
  echo "frontend_url=$FRONTEND_URL"
} > "$OUT_ABS/environment.txt"

cat > "$OUT_ABS/claim-boundary.txt" <<'EOF_BOUNDARY'
This is an evidence-capture package for AUD-628-P1-001 only.
It does not, by itself, close AUD-628-P1-001.
It does not claim public beta readiness, mainnet readiness, public validator safety,
live economics, production helper execution, automatic upgrade readiness, or legal approval.
A reviewer must confirm that the machine and operator are external to the founder and that
all required evidence files were captured from the documented commit and environment.
EOF_BOUNDARY

cat > "$OUT_ABS/commands.txt" <<EOF_COMMANDS
cd WeAll-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published registry signer public key>
bash scripts/boot_public_observer_testnet.sh
bash scripts/capture_public_observer_open_download_transcript_v1_5.sh --api-base '$API_BASE' --registry '$REGISTRY' --out-dir '$OUT_ABS'${FRONTEND_URL:+ --frontend-url '$FRONTEND_URL'}
EOF_COMMANDS

python scripts/gen_public_observer_launch_transcript_v1_5.py \
  --runtime-json \
  --api-base "$API_BASE" \
  --registry "$REGISTRY" \
  --out "$OUT_ABS/public_observer_launch_runtime_transcript_v1_5.json" \
  > "$OUT_ABS/logs/runtime-transcript.stdout.txt" 2> "$OUT_ABS/logs/runtime-transcript.stderr.txt" || true

for route in \
  /v1/status \
  /v1/chain/identity \
  /v1/chain/head \
  /v1/nodes/seeds \
  /v1/nodes/validators \
  /v1/observer/edge/status
  do
    safe="${route#/}"
    safe="${safe//\//_}"
    curl -fsS "$API_BASE$route" \
      > "$OUT_ABS/api/${safe}.json" \
      2> "$OUT_ABS/logs/${safe}.stderr.txt" || true
  done

cat > "$OUT_ABS/frontend/RENDERED_JOURNEY_CHECKLIST.md" <<EOF_FRONTEND
# Rendered frontend journey checklist

- Frontend URL: ${FRONTEND_URL:-<record local or deployed URL>}
- Screenshot/video artifact path: <attach path>
- Browser and OS: <record browser/version/os>

## Required surfaces

- [ ] Home shows bounded public-observer / controlled-testnet wording.
- [ ] Current node, chain_id, height, finalized height, and authority level are visible.
- [ ] Personal Node shows observer/operator/validator-candidate/validator authority separation.
- [ ] Seed/peer status is visible or an honest unavailable state is shown.
- [ ] Transaction lifecycle distinguishes submitted, locally accepted, queued, forwarded, included, finalized, rejected, removed, and unknown states.
- [ ] Account/profile state distinguishes public chain state from local draft/UI preferences.
- [ ] Feed/social surfaces state that protocol-native social activity is public.
- [ ] Groups state that reading is public and membership gates participation only.
- [ ] Governance shows block-height deadlines and record-only protocol/constitution upgrade boundaries.
- [ ] Disputes show public outcome/reasoning records and protected raw identity evidence boundaries.
- [ ] No UI claims public beta, mainnet, public validator safety, live economics, automatic upgrades, production helper execution, legal approval, or public storage-market readiness.
EOF_FRONTEND

python - "$OUT_ABS" <<'PY' > "$OUT_ABS/manifest.json"
from __future__ import annotations
from pathlib import Path
import hashlib, json, sys
root = Path(sys.argv[1])
files = {}
for path in sorted(p for p in root.rglob("*") if p.is_file()):
    rel = path.relative_to(root).as_posix()
    files[rel] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size_bytes": path.stat().st_size,
    }
payload = {
    "schema": "weall.v1_5.public_observer_open_download_transcript_manifest",
    "blocker": "AUD-628-P1-001",
    "ok": bool(files),
    "public_beta_ready": False,
    "public_observer_launch_ready": False,
    "external_review_required_before_closure": True,
    "files": files,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY

echo "wrote public observer open-download transcript package: $OUT_ABS"
echo "review $OUT_ABS/claim-boundary.txt before using this evidence in a release gate"
