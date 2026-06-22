from __future__ import annotations

import json
import os
import subprocess
import sys


def test_observer_to_validator_genesis_launch_flow_has_protocol_gates_not_manual_activation():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    proc = subprocess.run(
        [sys.executable, "scripts/gen_observer_to_validator_launch_flow_v1_5.py", "--json"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "weall.v1_5.observer_to_validator_launch_flow"
    assert payload["maintainer_manual_activation_authority"] is False
    assert payload["observer_validator_signing_enabled_by_boot_script"] is False
    flow_text = json.dumps(payload["flow"], sort_keys=True)
    assert "PoH" in flow_text
    assert "Tier 2" in flow_text
    assert "responsibility opt-in" in flow_text
    assert "epoch-open boundary" in flow_text
