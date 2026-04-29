from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "scripts" / "devnet_run_cross_node_convergence_live.sh"


def test_devnet_cross_node_live_runner_syntax_valid_batch223() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(RUNNER)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_devnet_cross_node_live_runner_documents_operational_knobs_batch223() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "WEALL_DEVNET_LIVE_RESET" in text
    assert "WEALL_DEVNET_KEEP_NODES" in text
    assert "WEALL_DEVNET_LIVE_LOG_DIR" in text
    assert "NODE1_API" in text
    assert "NODE2_API" in text


def test_devnet_cross_node_live_runner_starts_both_nodes_and_probe_batch223() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "devnet_boot_genesis_node.sh" in text
    assert "devnet_boot_joining_node.sh" in text
    assert "devnet_cross_node_convergence.sh" in text
    assert "wait_http_ready \"node1\"" in text
    assert "wait_http_ready \"node2\"" in text


def test_devnet_cross_node_live_runner_has_cleanup_and_logs_batch223() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "trap cleanup EXIT INT TERM" in text
    assert "kill \"${NODE1_PID}\"" in text
    assert "kill \"${NODE2_PID}\"" in text
    assert "tail -80 \"${NODE1_LOG}\"" in text
    assert "tail -80 \"${NODE2_LOG}\"" in text


def test_devnet_cross_node_live_runner_uses_normal_devnet_flow_not_demo_seed_batch223() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "/v1/dev/demo-seed" not in text
    assert "demo-seed" not in text
    assert "devnet_reset_state.sh" in text
    assert "devnet_cross_node_convergence.sh" in text


def test_devnet_cross_node_live_runner_recreates_log_dir_after_reset_batch224() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    reset_index = text.index("devnet_reset_state.sh")
    mkdir_index = text.index('mkdir -p "${LOG_DIR}"')
    truncate_index = text.index(': > "${NODE1_LOG}"')
    assert reset_index < mkdir_index < truncate_index
    assert "devnet_reset_state.sh removes .weall-devnet" in text


def test_devnet_cross_node_live_runner_auto_activates_repo_venv_batch226() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "WEALL_DEVNET_AUTO_VENV" in text
    assert "activate_repo_venv" in text
    assert 'source "${activate_path}"' in text
    assert text.index("activate_repo_venv") < text.index('NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"')


def test_devnet_boot_scripts_auto_activate_repo_venv_batch226() -> None:
    for name in ["devnet_boot_genesis_node.sh", "devnet_boot_joining_node.sh"]:
        script = REPO_ROOT / "scripts" / name
        text = script.read_text(encoding="utf-8")
        assert "WEALL_DEVNET_AUTO_VENV" in text
        assert "activate_repo_venv" in text
        assert 'source "${activate_path}"' in text
        assert "python3 scripts/devnet_tx.py ensure-keyfile" in text
        assert text.index("activate_repo_venv") < text.index("python3 scripts/devnet_tx.py ensure-keyfile")
