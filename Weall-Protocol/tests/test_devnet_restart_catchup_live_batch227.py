from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "scripts" / "devnet_restart_catchup_live.sh"


def test_devnet_restart_catchup_live_syntax_valid_batch227() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(RUNNER)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_devnet_restart_catchup_live_documents_operational_knobs_batch227() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "WEALL_DEVNET_LIVE_RESET" in text
    assert "WEALL_DEVNET_KEEP_NODES" in text
    assert "WEALL_DEVNET_LIVE_LOG_DIR" in text
    assert "WEALL_DEVNET_AUTO_VENV" in text
    assert "WEALL_DEVNET_READY_TIMEOUT" in text
    assert "NODE1_API" in text
    assert "NODE2_API" in text


def test_devnet_restart_catchup_live_uses_normal_devnet_flow_not_demo_seed_batch227() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "/v1/dev/demo-seed" not in text
    assert "demo-seed" not in text
    assert "devnet_boot_genesis_node.sh" in text
    assert "devnet_boot_joining_node.sh" in text
    assert "devnet_cross_node_convergence.sh" in text
    assert "devnet_sync_from_peer.sh" in text
    assert "devnet_compare_state_roots.sh" in text


def test_devnet_restart_catchup_live_restarts_both_nodes_batch227() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "stop_node2_for_restart" in text
    assert "stop_node1_for_restart" in text
    assert "after-node2-restart-catchup" in text
    assert "after-node1-restart-catchup" in text
    assert text.count("start_node1") >= 2
    assert text.count("start_node2") >= 2


def test_devnet_restart_catchup_live_syncs_and_compares_after_restart_batch227() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    node2_restart_index = text.index("after-node2-restart-catchup")
    node1_restart_index = text.index("after-node1-restart-catchup")
    assert text.index("sync_node1_to_node2", node2_restart_index - 300) < node2_restart_index
    assert text.index("sync_node1_to_node2", node1_restart_index - 300) < node1_restart_index
    assert "compare_roots \"after-node2-restart-catchup\"" in text
    assert "compare_roots \"after-node1-restart-catchup\"" in text


def test_devnet_restart_catchup_live_auto_activates_repo_venv_batch227() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "activate_repo_venv" in text
    assert 'source "${activate_path}"' in text
    assert text.index("activate_repo_venv") < text.index('NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"')


def test_devnet_restart_catchup_live_has_readiness_diagnostics_batch227() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "emit_log_tail_json" in text
    assert "node1 failed readiness" in text
    assert "node2 failed readiness" in text
    assert "tail -80 \"${NODE1_LOG}\"" in text
    assert "tail -80 \"${NODE2_LOG}\"" in text
