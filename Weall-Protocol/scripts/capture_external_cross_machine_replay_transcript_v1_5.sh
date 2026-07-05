#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/capture_external_cross_machine_replay_transcript_v1_5.sh \
    --machine-id <external-machine-id> \
    --operator-id <external-operator-id> \
    --out-dir <evidence-dir> \
    [--chain-id-prefix <prefix>]

Captures one machine's replay evidence packet for AUD-618-P1-003.
This is evidence capture only. It does not close AUD-618-P1-003, claim public
beta readiness, claim mainnet readiness, or prove public validator safety.

Run this from a clean checkout on each external/physical machine, then combine
the resulting LOCAL_MACHINE_REPLAY_EVIDENCE.json files into the aggregate
TRANSCRIPT_TEMPLATE.json and validate it with:

  PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
    --kind external_cross_machine_replay_transcript \
    --path docs/proofs/external-cross-machine-replay/<date>/<operator>/TRANSCRIPT.json
USAGE
}

MACHINE_ID=""
OPERATOR_ID=""
OUT_DIR=""
CHAIN_ID_PREFIX="external-cross-machine-replay"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --machine-id) MACHINE_ID="${2:-}"; shift 2 ;;
    --operator-id) OPERATOR_ID="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --chain-id-prefix) CHAIN_ID_PREFIX="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$MACHINE_ID" || -z "$OPERATOR_ID" || -z "$OUT_DIR" ]]; then
  echo "missing required --machine-id, --operator-id, or --out-dir" >&2
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
mkdir -p "$OUT_ABS/logs" "$OUT_ABS/artifacts"

cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
export WEALL_MODE=testnet
export WEALL_REQUIRE_VRF=0

{
  echo "weall external cross-machine replay evidence"
  echo "schema=weall.v1_5.external_cross_machine_replay_local_packet"
  echo "blocker=AUD-618-P1-003"
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root=$ROOT"
  echo "machine_id=$MACHINE_ID"
  echo "operator_id=$OPERATOR_ID"
  echo "chain_id_prefix=$CHAIN_ID_PREFIX"
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

STATE_ROOT_SHA="$(python - <<'PY'
from pathlib import Path
import hashlib
p=Path('generated/state_root_vectors_v1_5.json')
print(hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else 'missing')
PY
)"
TX_INDEX_SHA="$(python - <<'PY'
from pathlib import Path
import hashlib
p=Path('generated/tx_index.json')
print(hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else 'missing')
PY
)"
TX_CONTRACT_SHA="$(python - <<'PY'
from pathlib import Path
import hashlib
p=Path('generated/tx_contract_map.json')
print(hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else 'missing')
PY
)"

TMP_WORK="$OUT_ABS/replay-work"
mkdir -p "$TMP_WORK"

python scripts/replay_consistency_audit.py \
  --work-dir "$TMP_WORK" \
  --chain-id-prefix "$CHAIN_ID_PREFIX" \
  --json \
  > "$OUT_ABS/artifacts/replay_consistency_audit.json" \
  2> "$OUT_ABS/logs/replay_consistency_audit.stderr.txt"

python scripts/rehearse_fresh_node_replay_sync_v1_5.py \
  --json \
  > "$OUT_ABS/artifacts/fresh_node_replay_sync.json" \
  2> "$OUT_ABS/logs/fresh_node_replay_sync.stderr.txt"

python scripts/check_tx_canon_artifacts.py \
  > "$OUT_ABS/logs/check_tx_canon_artifacts.stdout.txt" \
  2> "$OUT_ABS/logs/check_tx_canon_artifacts.stderr.txt"

python - "$OUT_ABS" "$MACHINE_ID" "$OPERATOR_ID" "$STATE_ROOT_SHA" "$TX_INDEX_SHA" "$TX_CONTRACT_SHA" <<'PY' > "$OUT_ABS/LOCAL_MACHINE_REPLAY_EVIDENCE.json"
from __future__ import annotations
from pathlib import Path
import hashlib, json, subprocess, sys

root = Path(sys.argv[1])
machine_id, operator_id, state_root_sha, tx_index_sha, tx_contract_sha = sys.argv[2:7]
replay = json.loads((root / 'artifacts' / 'replay_consistency_audit.json').read_text(encoding='utf-8'))
fresh = json.loads((root / 'artifacts' / 'fresh_node_replay_sync.json').read_text(encoding='utf-8'))

def git(*args: str) -> str:
    proc = subprocess.run(['git', *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ''

files = {}
for path in sorted(p for p in root.rglob('*') if p.is_file()):
    rel = path.relative_to(root).as_posix()
    files[rel] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size_bytes': path.stat().st_size}

payload = {
    'schema': 'weall.v1_5.external_cross_machine_replay_local_packet',
    'blocker': 'AUD-618-P1-003',
    'machine_id': machine_id,
    'operator_id': operator_id,
    'commit': git('rev-parse', 'HEAD'),
    'branch': git('branch', '--show-current'),
    'git_status_short': git('status', '--short', '--untracked-files=all'),
    'state_root_vectors_sha256': state_root_sha,
    'tx_index_sha256': tx_index_sha,
    'tx_contract_map_sha256': tx_contract_sha,
    'replay_consistency_ok': bool(replay.get('ok')),
    'fresh_node_replay_sync_ok': bool(fresh.get('ok')),
    'state_root': str(replay.get('state_root') or replay.get('final_state_root') or replay.get('sample_state_root') or replay.get('state_root_after') or fresh.get('fresh_state_root') or ''),
    'fresh_state_root': str(fresh.get('fresh_state_root') or ''),
    'interrupted_resume_root': str(fresh.get('interrupted_resume_root') or ''),
    'tx_index_hash_source': 'generated/tx_index.json sha256',
    'files': files,
    'public_beta_ready': False,
    'mainnet_ready': False,
    'external_review_required_before_closure': True,
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
    'schema': 'weall.v1_5.external_cross_machine_replay_local_manifest',
    'blocker': 'AUD-618-P1-003',
    'ok': bool(files),
    'public_beta_ready': False,
    'mainnet_ready': False,
    'external_review_required_before_closure': True,
    'files': files,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY

cat > "$OUT_ABS/CLAIM_BOUNDARIES.md" <<'EOF_BOUNDARY'
# Claim boundaries

This is one local machine evidence packet for AUD-618-P1-003.
It does not close AUD-618-P1-003 by itself.
It does not prove public beta readiness, mainnet readiness, public validator safety,
live economics readiness, automatic upgrade readiness, production helper readiness,
legal/compliance approval, or public storage-market readiness.

A completed blocker-closing package requires at least two external/physical machine
packets from the same commit and same generated vector artifacts, then an aggregate
transcript that proves identical state roots and tx-index hashes.
EOF_BOUNDARY

echo "wrote local external cross-machine replay evidence packet: $OUT_ABS"
echo "combine at least two packets into docs/proofs/external-cross-machine-replay/<date>/<operator>/TRANSCRIPT.json before validation"
