from __future__ import annotations

import os


def test_clean_observer_boot_script_uses_checked_in_registry_and_direct_p2p_without_validator_signing():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    text = open(os.path.join(root, "scripts", "boot_public_observer_testnet.sh"), encoding="utf-8").read()
    assert "public_testnet_seed_registry.json" in text
    assert "public_testnet_trust_roots.json" in text
    assert "load_public_seed_registry" in text
    assert "seed_registry_signature_status" in text
    assert "WEALL_NET_ENABLED=\"${WEALL_NET_ENABLED:-1}\"" in text
    assert "WEALL_NET_LOOP_AUTOSTART=\"${WEALL_NET_LOOP_AUTOSTART:-1}\"" in text
    assert "init_prod_node_identity.sh --emit-shell-env" in text
    assert "WEALL_VALIDATOR_SIGNING_ENABLED=\"${WEALL_VALIDATOR_SIGNING_ENABLED:-0}\"" in text
    assert "WEALL_BFT_ENABLED=\"${WEALL_BFT_ENABLED:-0}\"" in text
    assert "exec bash scripts/run_node.sh" in text
    assert "exec python3 -m weall.api" not in text
