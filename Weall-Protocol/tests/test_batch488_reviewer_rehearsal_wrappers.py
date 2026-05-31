from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD = "".join(chr(c) for c in (110, 108, 110, 101, 116))


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_reviewer_setup_installs_local_package_and_checks_import() -> None:
    text = _read("scripts/reviewer_setup_env.sh")
    assert "pip install -r requirements-dev.lock" in text
    assert "pip install -e ." in text
    assert "import weall" in text
    assert "check_tx_canon_artifacts.py" in text
    assert "secret_guard.sh" in text
    assert "verify_release_dependencies.sh" in text


def test_reviewer_setup_skips_release_tree_by_default() -> None:
    text = _read("scripts/reviewer_setup_env.sh")
    assert 'RUN_RELEASE_TREE="${WEALL_REVIEWER_SETUP_RELEASE_TREE:-0}"' in text
    assert "Skipping release-tree check by default" in text
    assert "run scripts/verify_release_tree.sh separately on a cleaned tree" in text


def test_reviewer_lan_genesis_builds_verified_bundle_and_prints_observer_command() -> None:
    text = _read("scripts/reviewer_lan_genesis_rehearsal.sh")
    assert "build_external_observer_bundle.py" in text
    assert "--authority-url" in text
    assert "https://weall-rehearsal-authority.invalid" in text
    assert "verify_node_operator_onboarding_bundle.py" in text
    assert "WEALL_ALLOW_PRIVATE_GENESIS_API=1" in text
    assert "boot_weall_node.sh" in text
    assert "reviewer_observer_rehearsal.sh" in text


def test_reviewer_observer_runs_remote_preflight_and_signed_gate() -> None:
    text = _read("scripts/reviewer_observer_rehearsal.sh")
    assert "/v1/health" in text
    assert "/v1/status" in text
    assert "/v1/chain/identity" in text
    assert "/v1/genesis/observer/readiness" in text
    assert "WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1" in text
    assert "WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1" in text
    assert "first_external_observer_reproducibility_gate.sh" in text
    assert "audit-metadata/reviewer-lan-rehearsal-" in text


def test_reviewer_quickstart_has_truth_boundary_and_no_old_grant_name() -> None:
    text = _read("docs/REVIEWER_LAN_REHEARSAL_QUICKSTART.md")
    assert "What this proves" in text
    assert "What this does not prove" in text
    assert "Machine A: Genesis" in text
    assert "Machine B: Observer" in text
    assert "reviewer_setup_env.sh" in text
    assert "reviewer_lan_genesis_rehearsal.sh" in text
    assert "reviewer_observer_rehearsal.sh" in text
    assert "public multi-validator BFT readiness" in text
    assert "live economics" in text
    assert OLD not in text.lower()
