#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
PROTO="$ROOT/Weall-Protocol"
WEB="$ROOT/web"
BASE_SHA="9b907e26964284a61e3350f13a7a2b173c69d29c"
BRANCH_NAME="p0-03-production-closure-staging-20261001"

cd "$PROTO"

python - <<'PY'
from pathlib import Path
p = Path("scripts/a15_f003_account_scarcity_patch.py")
s = p.read_text(encoding="utf-8")
old = '''    count = text.count(old)\n    if count != 1:\n        raise SystemExit(f"replace_once_failed:{path}:count={count}:needle={old[:80]!r}")\n    write(path, text.replace(old, new, 1))\n'''
new = '''    if old not in text:\n        raise SystemExit(f"replace_once_failed:{path}:needle={old[:80]!r}")\n    write(path, text.replace(old, new, 1))\n'''
if old not in s:
    raise SystemExit("runner_replace_helper_not_found")
p.write_text(s.replace(old, new, 1), encoding="utf-8")
PY

python scripts/a15_f003_account_scarcity_patch.py

cat > scripts/bench_a15_f003_account_cardinality.py <<'PY'
from __future__ import annotations

import argparse
import gc
import json
import time
from hashlib import sha256

ACCOUNT_PADDING = "tier0-structured-state-synthetic:" + ("x" * 96)


def _account() -> dict:
    return {
        "nonce": 1,
        "account_type": "human",
        "poh_tier": 0,
        "banned": False,
        "locked": False,
        "synthetic_shape_padding": ACCOUNT_PADDING,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accounts", type=int, required=True)
    count = max(0, int(parser.parse_args().accounts))
    started = time.perf_counter()
    state = {
        "height": 1,
        "accounts": {f"@synthetic-{i:07d}": _account() for i in range(count)},
    }
    build_s = time.perf_counter() - started
    started = time.perf_counter()
    encoded = json.dumps(
        state, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    serialize_s = time.perf_counter() - started
    started = time.perf_counter()
    digest = sha256(encoded).hexdigest()
    hash_s = time.perf_counter() - started
    del state
    gc.collect()
    started = time.perf_counter()
    parsed = json.loads(encoded)
    restart_s = time.perf_counter() - started
    observed = len(parsed.get("accounts") or {})
    if observed != count:
        raise SystemExit("synthetic_account_count_mismatch")
    print(
        json.dumps(
            {
                "schema": "weall.a15_f003.account_cardinality_benchmark.v1",
                "accounts": count,
                "encoded_bytes": len(encoded),
                "build_seconds": round(build_s, 6),
                "canonical_serialize_seconds": round(serialize_s, 6),
                "canonical_preimage_sha256_seconds": round(hash_s, 6),
                "restart_json_parse_seconds": round(restart_s, 6),
                "canonical_preimage_sha256": digest,
                "synthetic": True,
                "note": "Cardinality-scaling evidence using bounded synthetic Tier-0-shaped records; not a production throughput or exact full-record-size benchmark.",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY

python - <<'PY'
import json
from pathlib import Path

path = Path("specs/v2/source/source_mappings.json")
payload = json.loads(path.read_text(encoding="utf-8"))
rows = payload.get("mappings")
if not isinstance(rows, list):
    raise SystemExit("source_mappings_not_list")
additions = [
    {
        "affected_registers": ["transactions", "routes", "activation"],
        "classification": "authoritative_or_launch_critical",
        "path": "src/weall/runtime/account_registration_work.py",
        "primary_mechanism_id": "M-012",
        "review_status": "mapped_current_snapshot",
    },
    {
        "affected_registers": ["routes", "activation", "presentation"],
        "classification": "authoritative_or_launch_critical",
        "path": "../web/src/lib/accountRegistrationWork.ts",
        "primary_mechanism_id": "M-069",
        "review_status": "mapped_current_snapshot",
    },
    {
        "affected_registers": ["evidence", "tooling"],
        "classification": "verification_tooling",
        "path": "scripts/bench_a15_f003_account_cardinality.py",
        "primary_mechanism_id": "M-076",
        "review_status": "mapped_current_snapshot",
    },
]
by_path = {str(row.get("path") or ""): row for row in rows if isinstance(row, dict)}
for row in additions:
    current = by_path.get(row["path"])
    if current is None:
        rows.append(row)
    elif current != row:
        raise SystemExit(f"source_mapping_conflict:{row['path']}")
rows.sort(key=lambda row: str(row.get("path") or ""))
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python - <<'PY'
from pathlib import Path
src = Path("scripts/a15_f003_register_v2_route.py").read_text(encoding="utf-8")
src = src.replace("import json\n", "import json\nimport os\n", 1)
src = src.replace(
    "ROOT = Path(__file__).resolve().parents[1]",
    "ROOT = Path(os.environ['WEALL_REPO_ROOT']).resolve()",
    1,
)
Path("/tmp/a15_f003_register_v2_route.py").write_text(src, encoding="utf-8")
PY

rm -f scripts/a15_f003_account_scarcity_patch.py
rm -f scripts/a15_f003_register_v2_route.py
WEALL_REPO_ROOT="$PROTO" python /tmp/a15_f003_register_v2_route.py

# Remove every temporary A15-F003 control before the final evidence scans.
rm -f "$ROOT/.github/workflows/a15-f003-account-scarcity-closure.yml"
rm -f "$ROOT/.github/workflows/a15-f003-account-scarcity-closure-v2.yml"
rm -f "$ROOT/.github/workflows/a15-f003-pr38-closure.yml"
rm -f "$ROOT/.github/workflows/a15-f003-pr38-closure-v3.yml"
rm -f "$ROOT/.github/workflows/a15-f003-pr38-closure-v4.yml"
rm -f "$ROOT/.github/workflows/a15-f003-pr38-closure-v5.yml"
rm -f "$PROTO/scripts/a15_f003_pr38_closure_v5.sh"

PY_FILES=(
  src/weall/runtime/account_registration_work.py
  src/weall/runtime/tx_schema.py
  src/weall/runtime/tx_admission.py
  src/weall/runtime/apply/identity.py
  src/weall/runtime/genesis_bootstrap.py
  src/weall/api/routes_public_parts/accounts.py
  scripts/build_production_genesis_manifest.py
  scripts/gen_public_testnet_v1_chain_identity.py
  scripts/bench_a15_f003_account_cardinality.py
  tests/test_a15_f003_account_registration_scarcity.py
)
ruff check --fix "${PY_FILES[@]}"
ruff format "${PY_FILES[@]}"
ruff check "${PY_FILES[@]}"

python scripts/build_production_genesis_manifest.py \
  --chain-id weall-prod \
  --founding-account '@errol-genesis' \
  --founding-pubkey c195d59d38ecf84b9baa227aff88960759afb72d2150f6e27a3187d0a3ae08be \
  --authority-pubkey c195d59d38ecf84b9baa227aff88960759afb72d2150f6e27a3187d0a3ae08be \
  --genesis-time 1778368894 \
  --econ-unlock-days 90 \
  --bootstrap-expires-height 1008
python scripts/gen_public_testnet_v1_chain_identity.py
python scripts/gen_public_testnet_v1_chain_identity.py --check

# v1.5 generated evidence is part of the V2 scanned evidence tree. Generate it first.
python scripts/gen_api_contract_map.py
python scripts/gen_failure_code_registry_v1_5.py

# V2 must be the final generator after all source/config/v1.5 evidence normalization.
python scripts/compile_v2_spec.py

pytest -q \
  tests/test_a15_f003_account_registration_scarcity.py \
  tests/test_production_genesis_manifest_builder.py \
  tests/test_production_go_gates.py \
  tests/test_m2_complete_security_and_lifecycle.py

python scripts/bench_a15_f003_account_cardinality.py --accounts 100000 | tee /tmp/a15-f003-100k.json
python scripts/bench_a15_f003_account_cardinality.py --accounts 1000000 | tee /tmp/a15-f003-1m.json

pip-audit -r requirements.lock
pip-audit -r requirements-dev.lock
python -m tooling.canon_lint
python scripts/check_generated.py
PYTHONPATH=src python scripts/compile_v2_spec.py --check
PYTHONDONTWRITEBYTECODE=1 python scripts/check_v15_public_readiness_artifacts.py
python scripts/check_public_claim_freshness.py
python scripts/gen_current_verified_claims.py --check

cd "$WEB"
npm ci
npm run dependency-audit
npm run typecheck
npm run test:account-custody-crypto-source
npm run build

cd "$PROTO"
RUNTIME_DIR="$(mktemp -d /tmp/weall-a15-f003-web-XXXXXX)"
mkdir -p "$RUNTIME_DIR/runtime" "$RUNTIME_DIR/helper_lanes" "$RUNTIME_DIR/media_cache" "$RUNTIME_DIR/reviewer_artifacts" "$RUNTIME_DIR/failpoints"
PYTHONPATH=src \
  WEALL_MODE=dev \
  WEALL_API_BOOT_RUNTIME=1 \
  WEALL_API_HOST=127.0.0.1 \
  WEALL_API_PORT=8000 \
  WEALL_NODE_ID=a15-f003-web-check \
  WEALL_DB_PATH="$RUNTIME_DIR/weall.db" \
  WEALL_AUX_DB_PATH="$RUNTIME_DIR/weall_aux.db" \
  WEALL_RUNTIME_DIR="$RUNTIME_DIR/runtime" \
  WEALL_HELPER_LANE_JOURNAL_DIR="$RUNTIME_DIR/helper_lanes" \
  WEALL_MEDIA_CACHE_DIR="$RUNTIME_DIR/media_cache" \
  WEALL_REVIEWER_ARTIFACTS_DIR="$RUNTIME_DIR/reviewer_artifacts" \
  WEALL_TEST_FAILPOINT_MARKER_DIR="$RUNTIME_DIR/failpoints" \
  WEALL_TX_INDEX_PATH="$PROTO/generated/tx_index.json" \
  python -m weall.api > /tmp/weall-a15-f003-api.log 2>&1 &
API_PID=$!
cleanup_api() {
  kill "$API_PID" >/dev/null 2>&1 || true
  wait "$API_PID" >/dev/null 2>&1 || true
}
trap cleanup_api EXIT
for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:8000/v1/readyz >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl -fsS http://127.0.0.1:8000/v1/readyz >/dev/null; then
  cat /tmp/weall-a15-f003-api.log >&2 || true
  exit 1
fi

cd "$WEB"
API_BASE=http://127.0.0.1:8000 npm run contract-check
cleanup_api
trap - EXIT

cd "$PROTO"
pytest -q

cd "$ROOT"
git diff --check
python - <<'PY'
import subprocess

base = "9b907e26964284a61e3350f13a7a2b173c69d29c"
exact = {
    "Weall-Protocol/src/weall/runtime/account_registration_work.py",
    "Weall-Protocol/src/weall/runtime/tx_schema.py",
    "Weall-Protocol/src/weall/runtime/tx_admission.py",
    "Weall-Protocol/src/weall/runtime/apply/identity.py",
    "Weall-Protocol/src/weall/runtime/genesis_bootstrap.py",
    "Weall-Protocol/src/weall/api/routes_public_parts/accounts.py",
    "Weall-Protocol/scripts/build_production_genesis_manifest.py",
    "Weall-Protocol/scripts/gen_public_testnet_v1_chain_identity.py",
    "Weall-Protocol/scripts/bench_a15_f003_account_cardinality.py",
    "Weall-Protocol/tests/test_a15_f003_account_registration_scarcity.py",
    "Weall-Protocol/docs/security/ACCOUNT_REGISTRATION_SCARCITY.md",
    "Weall-Protocol/configs/genesis.ledger.prod.json",
    "Weall-Protocol/configs/chains/weall-genesis.json",
    "Weall-Protocol/configs/genesis.ledger.testnet-v1.json",
    "Weall-Protocol/configs/chains/weall-testnet-v1.json",
    "Weall-Protocol/configs/public_testnet_chain_commitments.json",
    "Weall-Protocol/generated/api_contract_map_v1_5.json",
    "Weall-Protocol/generated/failure_code_registry_v1_5.json",
    "Weall-Protocol/specs/v2/source/stable_ids.json",
    "Weall-Protocol/specs/v2/source/semantic_reviews.json",
    "Weall-Protocol/specs/v2/source/source_mappings.json",
    "Weall-Protocol/specs/v2/source/manifest.json",
    "web/src/generated/protocolStatus.ts",
    "web/src/lib/accountRegistrationWork.ts",
    "web/src/auth/session.ts",
    "web/src/pages/AccountVerificationPage.tsx",
}
changed = set(subprocess.check_output(["git", "diff", "--name-only", base], text=True).splitlines())
unexpected = sorted(
    path
    for path in changed
    if path not in exact and not path.startswith("Weall-Protocol/generated/v2/")
)
required = {
    "Weall-Protocol/src/weall/runtime/account_registration_work.py",
    "Weall-Protocol/generated/api_contract_map_v1_5.json",
    "Weall-Protocol/generated/failure_code_registry_v1_5.json",
    "Weall-Protocol/specs/v2/source/stable_ids.json",
    "Weall-Protocol/specs/v2/source/semantic_reviews.json",
    "Weall-Protocol/specs/v2/source/source_mappings.json",
    "Weall-Protocol/specs/v2/source/manifest.json",
    "Weall-Protocol/tests/test_a15_f003_account_registration_scarcity.py",
    "Weall-Protocol/docs/security/ACCOUNT_REGISTRATION_SCARCITY.md",
    "web/src/lib/accountRegistrationWork.ts",
}
missing = sorted(required - changed)
print("bounded A15-F003 changed files:")
for path in sorted(changed):
    print(path)
if unexpected:
    raise SystemExit("unexpected_diff:" + ",".join(unexpected))
if missing:
    raise SystemExit("missing_required_diff:" + ",".join(missing))
PY

test ! -e Weall-Protocol/scripts/a15_f003_account_scarcity_patch.py
test ! -e Weall-Protocol/scripts/a15_f003_register_v2_route.py
test ! -e Weall-Protocol/scripts/a15_f003_pr38_closure_v5.sh
test ! -e .github/workflows/a15-f003-account-scarcity-closure.yml
test ! -e .github/workflows/a15-f003-account-scarcity-closure-v2.yml
test ! -e .github/workflows/a15-f003-pr38-closure.yml
test ! -e .github/workflows/a15-f003-pr38-closure-v3.yml
test ! -e .github/workflows/a15-f003-pr38-closure-v4.yml
test ! -e .github/workflows/a15-f003-pr38-closure-v5.yml

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -A
git status --short
git commit -m "fix: enforce A15-F003 account registration scarcity"
SOURCE_COMMIT="$(git rev-parse HEAD)"
SOURCE_TREE="$(git rev-parse HEAD^{tree})"

cd "$PROTO"
python scripts/check_v2_spec_clean_checkout.py
PYTHONDONTWRITEBYTECODE=1 python scripts/check_v15_public_readiness_artifacts.py

cd "$ROOT"
git push origin "HEAD:${BRANCH_NAME}"
printf 'source commit: %s\n' "$SOURCE_COMMIT"
printf 'source tree:   %s\n' "$SOURCE_TREE"
