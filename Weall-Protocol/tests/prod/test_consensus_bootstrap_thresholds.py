from __future__ import annotations

import json
import os
import subprocess
import sys


def test_consensus_bootstrap_thresholds_artifact_records_bft_boundary():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    proc = subprocess.run(
        [sys.executable, "scripts/gen_consensus_bootstrap_thresholds_v1_5.py", "--json"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "weall.v1_5.consensus_bootstrap_thresholds"
    assert payload["bft_min_validators"] == 4
    counts = {row["active_validator_count"]: row for row in payload["counts"]}
    assert counts[1]["consensus_phase"] == "solo_bootstrap"
    assert counts[3]["hotstuff_bft_active"] is False
    assert counts[4]["hotstuff_bft_active"] is True
    assert counts[4]["quorum_threshold"] == 3
    assert payload["bootstrap_rules"]["maintainer_manual_activation_authority"] is False


def test_public_launch_artifacts_expose_static_partial_until_live_rehearsal():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    proc = subprocess.run(
        [sys.executable, "scripts/gen_genesis_testnet_launch_readiness_v1_5.py", "--json"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "weall.v1_5.genesis_testnet_launch_readiness"
    assert payload["checked_in_registry_baseline"] is True
    assert payload["direct_p2p_primary"] is True
    assert payload["relay_fallback_only"] is True
    assert payload["manual_validator_activation_authority"] is False
    assert payload["overall_launch_verdict"] == "partial_until_live_genesis_reachability_and_rehearsal_pass"
    assert payload["observer_boot_script_checks"]["enables_direct_p2p_mesh_loop"] is True
