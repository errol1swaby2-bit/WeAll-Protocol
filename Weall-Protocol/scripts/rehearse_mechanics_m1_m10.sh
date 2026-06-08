#!/usr/bin/env bash
set -euo pipefail

# Mechanics-first M-1 through M-10 gate.
#
# Default mode is hermetic/static and safe for CI/reviewer clones. Optional live
# modes require locally running nodes and are opt-in so this script never enables
# public validators, live economics, automatic upgrades, or helper production.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

RUN_BFT_LOCAL=0
RUN_STATE_SYNC_LIVE=0
RUN_NETWORK_LIVE=0

for arg in "$@"; do
  case "$arg" in
    --bft-local) RUN_BFT_LOCAL=1 ;;
    --state-sync-live) RUN_STATE_SYNC_LIVE=1 ;;
    --network-live) RUN_NETWORK_LIVE=1 ;;
    --all-live)
      RUN_BFT_LOCAL=1
      RUN_STATE_SYNC_LIVE=1
      RUN_NETWORK_LIVE=1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/rehearse_mechanics_m1_m10.sh [--bft-local] [--state-sync-live] [--network-live]

Default checks:
  - regenerate/check M-1..M-10 mechanics register
  - regenerate/check state-root vectors
  - regenerate/check locked tokenomics simulation
  - run M-1..M-10 unit tests

Optional checks:
  --bft-local        run local adversarial BFT matrices without enabling public validators
  --state-sync-live  run existing two-node state sync harness against NODE1_API/NODE2_API
  --network-live     run existing two-node cross-node convergence harness
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

python3 scripts/gen_mechanics_gap_register_v1_5.py
python3 scripts/gen_state_root_vectors_v1_5.py
python3 scripts/gen_tokenomics_simulation_v1_5.py

python3 scripts/gen_mechanics_gap_register_v1_5.py --check
python3 scripts/gen_state_root_vectors_v1_5.py --check
python3 scripts/gen_tokenomics_simulation_v1_5.py --check

pytest -q tests/test_batch498_mechanics_m1_m10.py

if [[ "${RUN_BFT_LOCAL}" == "1" ]]; then
  echo "[mechanics] running local BFT adversarial matrices; public validators remain disabled"
  python3 scripts/bft_consensus_resilience_matrix.py
  python3 scripts/bft_adversarial_matrix.py
fi

if [[ "${RUN_STATE_SYNC_LIVE}" == "1" ]]; then
  echo "[mechanics] running live state-sync proof against configured NODE1_API/NODE2_API"
  bash scripts/devnet_sync_from_peer.sh "${NODE1_API:-http://127.0.0.1:8001}" "${NODE2_API:-http://127.0.0.1:8002}"
fi

if [[ "${RUN_NETWORK_LIVE}" == "1" ]]; then
  echo "[mechanics] running live cross-node convergence probe"
  python3 scripts/devnet_cross_node_convergence.py
fi

echo "[mechanics] OK: M-1 through M-10 static mechanics gate passed"
