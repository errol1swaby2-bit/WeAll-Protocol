from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fresh_node_operator_candidate_demo.sh"
QUICKSTART = ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_fresh_operator_candidate_demo_script_exists_and_is_safe_batch294():
    text = read(SCRIPT)
    assert "WEALL_FRESH_OPERATOR_DEMO_EXECUTE" in text
    assert "structural_smoke" in text
    assert "execute_candidate_path" in text
    assert "activation pending" in text.lower()
    assert "observer_onboarding" in text
    assert "production_service" in text
    assert "ROLE_NODE_OPERATOR_ENROLL" in text
    assert "ACCOUNT_DEVICE_REGISTER" in text
    assert "demo_native_async_tier1_e2e.sh" in text
    assert "devnet_request_live.sh" in text
    assert "WEALL_NODE_PRIVKEY_FILE" in text
    assert "weall_node_key" in text
    assert "ROLE_NODE_OPERATOR_ACTIVATE" not in text
    assert "WEALL_NODE_PRIVKEY=<account_secret>" not in text
    assert "WEALL_NODE_PRIVKEY=<localSecretKey>" not in text
    assert "bootstrap grant" not in text.lower()


def test_fresh_operator_candidate_demo_links_to_current_onboarding_assets_batch294():
    text = read(SCRIPT)
    for expected in [
        "boot_onboarding_node.sh",
        "boot_node_operator.sh",
        "docs/NEW_NODE_OPERATOR_QUICKSTART.md",
        "../web/src/pages/Account.tsx",
        "../web/src/auth/nodeKeys.ts",
    ]:
        assert expected in text


def test_quickstart_mentions_candidate_demo_without_overpromising_batch294():
    text = read(QUICKSTART)
    assert "./scripts/fresh_node_operator_candidate_demo.sh" in text
    assert "WEALL_FRESH_OPERATOR_DEMO_EXECUTE=1" in text
    assert "node-operator candidate / activation pending" in text
    assert "does not grant production node-operator authority" in text
    assert "WEALL_NODE_PRIVKEY=<account_secret>" not in text
    assert "WEALL_NODE_PRIVKEY=<localSecretKey>" not in text


def test_candidate_demo_smoke_runs_in_dry_mode_batch294():
    proc = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout
    assert "structural smoke OK" in proc.stdout
    assert "dry-run only" in proc.stdout
