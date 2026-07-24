#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m2_common.sh"
m2_activate_venv
ART="${M2_ARTIFACT_ROOT}/media"
mkdir -p "${ART}"
(
  cd "${M2_BACKEND}"
  PYTHONPATH=src python3 -m pytest -q \
    tests/test_apply_poh_live_replacement_e2e_mvp.py \
    tests/test_live_room_remote_media_recovery.py \
    tests/test_webrtc_bridge_replay_token_turn_cleanup.py \
    tests/test_cross_node_webrtc_bridge_and_accept_join.py \
    tests/test_restricted_poh_session_and_webrtc_transport.py \
    tests/test_poh_live_room_presence.py
) 2>&1 | tee "${ART}/media-interruption-replacement.txt"
# This source-level and API-level rehearsal is paired with the mandatory live
# independent-browser journey in run_m2_complete_closure.sh.
grep -Eq '[0-9]+ passed' "${ART}/media-interruption-replacement.txt"
echo "OK: M2 media interruption and reviewer replacement rehearsal passed"
