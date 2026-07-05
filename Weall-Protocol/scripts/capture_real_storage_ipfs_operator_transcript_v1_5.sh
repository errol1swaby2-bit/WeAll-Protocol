#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/capture_real_storage_ipfs_operator_transcript_v1_5.sh \
    --operator-id <storage-operator-id> \
    --machine-id <storage-machine-id> \
    --api-base <ipfs-api-base-url> \
    --out-dir <evidence-dir> \
    [--payload-file <path>]

Captures one real IPFS/Kubo daemon evidence packet for AUD-618-P1-004.
This is evidence capture only. It does not close AUD-618-P1-004, claim public
beta readiness, claim public decentralized media durability, or enable a public
storage-provider market.

Run this from a clean checkout on each real storage/IPFS operator machine.
A blocker-closing package still requires an aggregate transcript with at least
three distinct operators, three distinct machines, three distinct IPFS peer IDs,
non-origin retrieval, fresh-node retrieval, wrong-CID rejection, corrupt-content
rejection, revalidation evidence, external attestation, real_daemon_topology=true in the aggregate transcript, and reviewer approval.

Validate the aggregate transcript with:

  PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
    --kind storage_ipfs_operator_transcript \
    --strict-release \
    --path docs/proofs/real-storage-ipfs-operator/<date>/<operator>/TRANSCRIPT.json
USAGE
}

OPERATOR_ID=""
MACHINE_ID=""
API_BASE=""
OUT_DIR=""
PAYLOAD_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-id) OPERATOR_ID="${2:-}"; shift 2 ;;
    --machine-id) MACHINE_ID="${2:-}"; shift 2 ;;
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --payload-file) PAYLOAD_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$OPERATOR_ID" || -z "$MACHINE_ID" || -z "$API_BASE" || -z "$OUT_DIR" ]]; then
  echo "missing required --operator-id, --machine-id, --api-base, or --out-dir" >&2
  usage >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_ABS="$(python - "$OUT_DIR" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
mkdir -p "$OUT_ABS/api" "$OUT_ABS/payload" "$OUT_ABS/logs" "$OUT_ABS/artifacts"

cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1

if [[ -z "$PAYLOAD_FILE" ]]; then
  PAYLOAD_FILE="$OUT_ABS/payload/weall-storage-ipfs-aud-618-p1-004-payload.txt"
  cat > "$PAYLOAD_FILE" <<EOF_PAYLOAD
WeAll AUD-618-P1-004 real storage/IPFS operator evidence payload
operator=$OPERATOR_ID
machine=$MACHINE_ID
captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF_PAYLOAD
fi

PAYLOAD_ABS="$(python - "$PAYLOAD_FILE" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
if [[ ! -f "$PAYLOAD_ABS" ]]; then
  echo "payload file does not exist: $PAYLOAD_ABS" >&2
  exit 2
fi
cp "$PAYLOAD_ABS" "$OUT_ABS/payload/original_payload.bin"

curl_post() {
  local path="$1"
  shift
  curl -fsS -X POST "$@" "${API_BASE%/}${path}"
}

{
  echo "weall real storage/IPFS operator local evidence packet"
  echo "schema=weall.v1_5.storage_ipfs_operator_local_packet"
  echo "blocker=AUD-618-P1-004"
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root=$ROOT"
  echo "operator_id=$OPERATOR_ID"
  echo "machine_id=$MACHINE_ID"
  echo "api_base=$API_BASE"
  echo "payload_file=$PAYLOAD_ABS"
  echo "git_head=$(git rev-parse HEAD 2>/dev/null || true)"
  echo "git_branch=$(git branch --show-current 2>/dev/null || true)"
  echo "git_status_short_begin"
  git status --short --untracked-files=all 2>/dev/null || true
  echo "git_status_short_end"
  echo "python=$(python --version 2>&1)"
  echo "platform=$(python - <<'PY'
import platform
print(platform.platform())
PY
)"
} > "$OUT_ABS/environment.txt"

curl_post "/api/v0/version" > "$OUT_ABS/api/ipfs_version.json" 2> "$OUT_ABS/logs/ipfs_version.stderr.txt"
curl_post "/api/v0/id" > "$OUT_ABS/api/ipfs_id.json" 2> "$OUT_ABS/logs/ipfs_id.stderr.txt"
curl_post "/api/v0/add?pin=true&cid-version=1" -F "file=@${PAYLOAD_ABS}" > "$OUT_ABS/api/ipfs_add.json" 2> "$OUT_ABS/logs/ipfs_add.stderr.txt"

CID="$(python - "$OUT_ABS/api/ipfs_add.json" <<'PY'
from __future__ import annotations
import json, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding='utf-8').strip()
last = None
for line in text.splitlines():
    if line.strip():
        last = json.loads(line)
if not isinstance(last, dict) or not last.get('Hash'):
    raise SystemExit('missing IPFS Hash in add output')
print(last['Hash'])
PY
)"

curl_post "/api/v0/cat?arg=${CID}" -o "$OUT_ABS/payload/retrieved_payload.bin" 2> "$OUT_ABS/logs/ipfs_cat.stderr.txt"
curl_post "/api/v0/pin/ls?arg=${CID}&type=recursive" > "$OUT_ABS/api/ipfs_pin_ls.json" 2> "$OUT_ABS/logs/ipfs_pin_ls.stderr.txt"

set +e
curl_post "/api/v0/cat?arg=bafybeigdyrztbadwrongcidforweallaud618p1004" -o "$OUT_ABS/payload/wrong_cid_payload.bin" > "$OUT_ABS/logs/wrong_cid.stdout.txt" 2> "$OUT_ABS/logs/wrong_cid.stderr.txt"
WRONG_CID_STATUS=$?
set -e

echo "corrupt payload for negative content-addressing check" > "$OUT_ABS/payload/corrupt_payload.bin"

python - "$OUT_ABS" "$OPERATOR_ID" "$MACHINE_ID" "$CID" "$WRONG_CID_STATUS" <<'PY' > "$OUT_ABS/LOCAL_STORAGE_IPFS_EVIDENCE.json"
from __future__ import annotations
from pathlib import Path
import hashlib, json, subprocess, sys

root = Path(sys.argv[1])
operator_id, machine_id, cid, wrong_status = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])

def read_json(rel: str):
    return json.loads((root / rel).read_text(encoding='utf-8'))

def sha(rel: str) -> str:
    return hashlib.sha256((root / rel).read_bytes()).hexdigest()

def git(*args: str) -> str:
    proc = subprocess.run(['git', *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ''

version = read_json('api/ipfs_version.json')
peer = read_json('api/ipfs_id.json')
add = read_json('api/ipfs_add.json')
pin = read_json('api/ipfs_pin_ls.json')
orig_sha = sha('payload/original_payload.bin')
retrieved_sha = sha('payload/retrieved_payload.bin')
corrupt_sha = sha('payload/corrupt_payload.bin')

files = {}
for path in sorted(p for p in root.rglob('*') if p.is_file()):
    rel = path.relative_to(root).as_posix()
    files[rel] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size_bytes': path.stat().st_size}

payload = {
    'schema': 'weall.v1_5.storage_ipfs_operator_local_packet',
    'blocker': 'AUD-618-P1-004',
    'operator_id': operator_id,
    'machine_id': machine_id,
    'commit': git('rev-parse', 'HEAD'),
    'branch': git('branch', '--show-current'),
    'git_status_short': git('status', '--short', '--untracked-files=all'),
    'ipfs_peer_id': str(peer.get('ID') or ''),
    'daemon_version': str(version.get('Version') or version),
    'payload_sha256': orig_sha,
    'retrieved_sha256': retrieved_sha,
    'corrupt_payload_sha256': corrupt_sha,
    'cid': cid,
    'publish_ok': bool(add.get('Hash') == cid),
    'pin_proof_present': bool(pin),
    'retrieval_ok': retrieved_sha == orig_sha,
    'wrong_cid_rejected': wrong_status != 0,
    'corrupt_content_rejected': retrieved_sha == orig_sha and corrupt_sha != orig_sha,
    'fresh_node_retrieval_requires_aggregate_evidence': True,
    'origin_failure_requires_aggregate_evidence': True,
    'revalidation_requires_aggregate_evidence': True,
    'public_beta_ready': False,
    'public_decentralized_media_durability': False,
    'public_storage_provider_market': False,
    'external_review_required_before_closure': True,
    'aggregate_requires_real_daemon_topology': True,
    'files': files,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY

python - "$OUT_ABS" <<'PY' > "$OUT_ABS/manifest.json"
from pathlib import Path
import hashlib, json, sys
root = Path(sys.argv[1])
files = {}
for path in sorted(p for p in root.rglob('*') if p.is_file()):
    rel = path.relative_to(root).as_posix()
    files[rel] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size_bytes': path.stat().st_size}
payload = {
    'schema': 'weall.v1_5.storage_ipfs_operator_local_manifest',
    'blocker': 'AUD-618-P1-004',
    'ok': bool(files),
    'public_beta_ready': False,
    'public_decentralized_media_durability': False,
    'public_storage_provider_market': False,
    'external_review_required_before_closure': True,
    'aggregate_requires_real_daemon_topology': True,
    'files': files,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY

cat > "$OUT_ABS/CLAIM_BOUNDARIES.md" <<'EOF_BOUNDARY'
# Claim boundaries

This is one real storage/IPFS local evidence packet for AUD-618-P1-004.
It does not close AUD-618-P1-004 by itself.
It does not prove public beta readiness, mainnet readiness, public decentralized
media durability, public storage-provider market readiness, live economics,
automatic upgrade readiness, production helper readiness, legal/compliance
approval, or public validator safety.

A blocker-closing package requires at least three distinct external/operator
machines with real daemon peer IDs, aggregate retrieval proofs, wrong-CID and
corrupt-content rejection, revalidation evidence, external attestation, and
strict-release validation of the aggregate transcript.
EOF_BOUNDARY

echo "wrote real storage/IPFS local evidence packet: $OUT_ABS"
echo "aggregate at least three packets into docs/proofs/real-storage-ipfs-operator/<date>/<operator>/TRANSCRIPT.json before strict-release validation"
