from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "devnet_full_onboarding_e2e.sh"


def _text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_full_onboarding_script_syntax_valid_batch228() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_full_onboarding_auto_activates_venv_before_python_helpers_batch228() -> None:
    text = _text()
    assert "WEALL_DEVNET_AUTO_VENV" in text
    assert "activate_repo_venv" in text
    assert "Activated Python virtualenv" in text
    assert text.index("activate_repo_venv") < text.index("_account_from_keyfile")


def test_full_onboarding_node2_convergence_supports_edge_relay_batch228() -> None:
    text = _text()
    assert "--tx-out \"${tx_file}\"" in text
    assert "Node 2 accepted convergence tx but did not confirm it locally" in text
    assert "relaying exact signed tx to canonical producer" in text
    assert "_submit_signed_tx_file_and_wait" in text
    assert "Syncing node 2 from node 1 after edge relay confirmation" in text
    assert "edge-relayed node-2-submitted tx" in text
    assert "WEALL_NODE2_CONVERGENCE_WAIT_TIMEOUT" in text


def test_full_onboarding_preserves_node2_producer_mode_batch228() -> None:
    text = _text()
    assert "Node 2 confirmed convergence tx locally" in text
    assert "Syncing node 1 from node 2 after node-2-submitted tx" in text
    assert "Comparing node roots after node-2-submitted tx" in text


def test_full_onboarding_uses_tier0_probe_when_email_is_skipped_batch228() -> None:
    text = _text()
    assert 'if [[ -n "${WEALL_EMAIL:-}" ]]' in text
    assert 'tx_type="FOLLOW_SET"' in text
    assert 'label="Tier-1-gated FOLLOW_SET"' in text
    assert 'tx_type="PROFILE_UPDATE"' in text
    assert 'label="Tier-0 PROFILE_UPDATE"' in text


def test_full_onboarding_edge_relay_stays_non_demo_batch228() -> None:
    text = _text()
    assert "/v1/dev/demo-seed" not in text
    assert "WEALL_ENABLE_DEMO_SEED_ROUTE" not in text
    assert "/v1/tx/submit" in text or "devnet_submit_tx_node2.sh" in text
