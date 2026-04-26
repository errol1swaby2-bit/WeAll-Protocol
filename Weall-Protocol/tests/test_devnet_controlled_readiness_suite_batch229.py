from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SUITE = REPO_ROOT / "scripts" / "devnet_controlled_readiness_suite.sh"
PERMISSION_LIVE = REPO_ROOT / "scripts" / "devnet_run_permission_probe_live.sh"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_batch229_scripts_are_syntax_valid() -> None:
    for script in [SUITE, PERMISSION_LIVE]:
        proc = subprocess.run(
            ["bash", "-n", str(script)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


def test_permission_live_runner_auto_activates_venv_and_reports_logs() -> None:
    text = _text(PERMISSION_LIVE)
    assert "WEALL_DEVNET_AUTO_VENV" in text
    assert "activate_repo_venv" in text
    assert "Activated Python virtualenv" in text
    assert "devnet_permission_probe.sh" in text
    assert "node1-permission-probe-live.log" in text
    assert "permission-probe-live.log" in text
    assert "dump_log_tail" in text


def test_permission_live_runner_stays_non_demo_and_signed_tx_only() -> None:
    text = _text(PERMISSION_LIVE)
    assert "/v1/dev/demo-seed" not in text
    assert "demo-seed" not in text
    assert "devnet_permission_probe.sh" in text
    assert "WEALL_ENABLE_DEMO_SEED_ROUTE" not in text
    assert "WEALL_BLOCK_LOOP_AUTOSTART" in text


def test_controlled_readiness_suite_runs_core_live_harnesses() -> None:
    text = _text(SUITE)
    assert "devnet_run_permission_probe_live.sh" in text
    assert "devnet_full_onboarding_e2e.sh" in text
    assert "devnet_run_cross_node_convergence_live.sh" in text
    assert "devnet_restart_catchup_live.sh" in text
    assert "WEALL_DEVNET_LIVE_RESET=1" in text
    assert "WEALL_DEVNET_RESET_ON_AUTOSTART=1" in text


def test_controlled_readiness_suite_has_tier2_tier3_email_guard() -> None:
    text = _text(SUITE)
    assert "require_email_for_tier_poh" in text
    assert "WEALL_DEVNET_SUITE_RUN_TIER2" in text
    assert "WEALL_DEVNET_SUITE_RUN_TIER3" in text
    assert "requires WEALL_EMAIL" in text
    assert "WEALL_DEVNET_RUN_TIER2" in text
    assert "WEALL_DEVNET_RUN_TIER3" in text


def test_controlled_readiness_suite_skip_knobs_and_no_demo_dependency() -> None:
    text = _text(SUITE)
    assert "WEALL_DEVNET_SUITE_RUN_PERMISSION" in text
    assert "WEALL_DEVNET_SUITE_RUN_ONBOARDING" in text
    assert "WEALL_DEVNET_SUITE_RUN_CROSS_NODE" in text
    assert "WEALL_DEVNET_SUITE_RUN_RESTART" in text
    assert "/v1/dev/demo-seed" not in text
    assert "demo-seed" not in text
