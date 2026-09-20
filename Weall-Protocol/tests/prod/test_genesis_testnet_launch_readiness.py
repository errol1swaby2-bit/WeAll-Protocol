from __future__ import annotations

import json
import os
import subprocess
import sys


def test_genesis_testnet_launch_readiness_generator_static_verdict():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    proc = subprocess.run(
        [sys.executable, "scripts/gen_genesis_testnet_launch_readiness_v1_5.py", "--json"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "weall.v1_5.genesis_testnet_launch_readiness"
    assert payload["registry"]["chain_id"] == "weall-testnet-v1"
    assert payload["registry"]["network_id"] == "weall-public-observer-testnet-v1"
    assert payload["registry"]["signature_status"]["verified"] is False
    assert payload["registry"]["signature_status"]["trust"] == "rotation_required"
    assert payload["static_readiness_verdict"] == "blocked"
    assert payload["registry"]["errors"] == ["public_testnet_seed_registry_rotation_required"]
    assert payload["observer_boot_script_checks"]["enables_direct_p2p_mesh_loop"] is True
    assert payload["observer_boot_script_checks"]["refuses_observer_validator_signing"] is True
    assert payload["named_provider_dependency"] is False
    assert (
        payload["overall_launch_verdict"]
        == "blocked_until_seed_registry_rotation_and_static_checks_pass"
    )
