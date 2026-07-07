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


def test_public_observer_quickstart_documents_first_and_second_observer_without_admin_shortcut():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    quickstart = open(os.path.join(root, "docs", "PUBLIC_OBSERVER_TESTNET_QUICKSTART.md"), encoding="utf-8").read()
    readme = open(os.path.join(root, "..", "README.md"), encoding="utf-8").read()

    assert "## First and second observer runbook" in quickstart
    assert "WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh" in quickstart
    assert "/v1/nodes/seeds" in quickstart
    assert "/v1/nodes/validators" in quickstart
    assert "/v1/chain/identity" in quickstart
    assert "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM" in quickstart
    assert "Local env flags" in quickstart
    assert "cannot grant validator authority" in quickstart
    assert "founder-only admin action" in quickstart
    assert "promoted-validator preflight" in quickstart
    assert "configs/public_testnet_seed_registry.json" in readme
    assert "configs/public_testnet_trust_roots.json" in readme
    assert "configs/chains/weall-testnet-v1.json" in readme
