from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_one_command_tester_node_script_exists_and_forces_observer_safety_batch468() -> None:
    script = _read("scripts/weall_tester_node.sh")

    assert "Usage: scripts/weall_tester_node.sh --bundle" in script
    assert "weall_check_observer_secret_boundary" in script
    assert "WEALL_NODE_LIFECYCLE_STATE=observer_onboarding" in script
    assert "WEALL_OBSERVER_MODE=1" in script
    assert "WEALL_VALIDATOR_SIGNING_ENABLED=0" in script
    assert "WEALL_BFT_ENABLED=0" in script
    assert "WEALL_HELPER_MODE_ENABLED=0" in script
    assert "WEALL_BLOCK_LOOP_AUTOSTART=0" in script
    assert "boot_onboarding_node.sh" in script
    assert "frontend" in script.lower()


def test_one_command_tester_node_installs_bundle_and_runtime_outside_repo_batch468() -> None:
    script = _read("scripts/weall_tester_node.sh")

    assert "install_node_operator_onboarding_bundle.py" in script
    assert "verify_node_operator_onboarding_bundle.py" in script
    assert "${HOME}/.weall/tester-node" in script
    assert "WEALL_DB_PATH=\"${RUNTIME_DIR}/observer.db\"" in script
    assert "WEALL_TX_QUEUE_PATH=\"${RUNTIME_DIR}/observer_tx_queue.json\"" in script
    assert "WEALL_TX_UPSTREAM_URLS" in script


def test_genesis_rehearsal_script_requires_matching_canonical_validator_key_batch468() -> None:
    script = _read("scripts/weall_genesis_rehearsal.sh")

    assert "--producer-pubkey-file" in script
    assert "--producer-privkey-file" in script
    assert "producer public key does not match canonical Genesis validator" in script
    assert "WEALL_VALIDATOR_SIGNING_ENABLED=1" in script
    assert "WEALL_REQUIRE_VRF=1" in script
    assert "normal observers must still run without producer secrets" in script


def test_tester_one_command_docs_exist_batch468() -> None:
    doc = _read("docs/TESTER_ONE_COMMAND_NODE_BOOT.md")

    assert "One-command tester node boot" in doc
    assert "scripts/weall_tester_node.sh" in doc
    assert "observer onboarding" in doc
    assert "does not grant validator" in doc
