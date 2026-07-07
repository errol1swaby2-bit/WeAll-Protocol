from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
DOC = ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md"
SMOKE = ROOT / "scripts" / "operator_onboarding_smoke.sh"
ONBOARDING = ROOT / "scripts" / "boot_onboarding_node.sh"
SERVICE = ROOT / "scripts" / "boot_node_operator.sh"
ACCOUNT_PAGE = OUTER / "web" / "src" / "pages" / "Account.tsx"
NODE_KEYS = OUTER / "web" / "src" / "auth" / "nodeKeys.ts"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_new_node_operator_quickstart_documents_full_safe_path() -> None:
    doc = read(DOC)

    assert "./scripts/boot_onboarding_node.sh" in doc
    assert "./scripts/boot_node_operator.sh" in doc
    assert "Create your account and save your recovery key" in doc
    assert "Verified Person / Tier 1" in doc
    assert "Trusted Verified Person / Tier 2" in doc
    assert "Generate and download node key" in doc
    assert "Register the node public key" in doc
    assert "Submit node-operator enrollment" in doc
    assert "Wait for protocol eligibility activation" in doc
    assert "WEALL_NODE_PRIVKEY_FILE" in doc
    assert "After enrollment, the protocol checks eligibility" in doc
    assert "Do not use your account recovery key as a node key" in doc


def test_new_node_operator_quickstart_does_not_reintroduce_unsafe_node_key_copy() -> None:
    doc = read(DOC)
    account_page = read(ACCOUNT_PAGE)

    forbidden = [
        "WEALL_NODE_PRIVKEY=<account_secret>",
        "WEALL_NODE_PRIVKEY=<localSecretKey>",
        "WEALL_NODE_PRIVKEY=${",
        "Paste your account secret as the node key",
        "Self-activation is available",
        "Activate node operator role",
    ]
    for needle in forbidden:
        assert needle not in doc
        assert needle not in account_page

    assert "WEALL_NODE_PRIVKEY_FILE=" in account_page
    assert "not from your account recovery key" in account_page


def test_operator_onboarding_smoke_script_checks_boot_split_and_ui_contract() -> None:
    smoke = read(SMOKE)

    assert "boot_onboarding_node.sh" in smoke
    assert "boot_node_operator.sh" in smoke
    assert "NEW_NODE_OPERATOR_QUICKSTART.md" in smoke
    assert "WEALL_NODE_LIFECYCLE_STATE" in smoke
    assert "observer_onboarding" in smoke
    assert "production_service" in smoke
    assert "WEALL_NODE_PRIVKEY_FILE" in smoke
    assert "ROLE_NODE_OPERATOR_ACTIVATE" in smoke
    assert "reject_text" in smoke


def test_operator_onboarding_smoke_script_passes() -> None:
    subprocess.run(["sh", str(SMOKE)], cwd=str(ROOT), check=True, timeout=15, capture_output=True, text=True)


def test_boot_scripts_match_quickstart_contract() -> None:
    doc = read(DOC)
    onboarding = read(ONBOARDING)
    service = read(SERVICE)
    node_keys = read(NODE_KEYS)

    assert "WEALL_NODE_LIFECYCLE_STATE=\"${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}\"" in onboarding
    assert "WEALL_OBSERVER_MODE=\"${WEALL_OBSERVER_MODE:-1}\"" in onboarding
    assert "WEALL_VALIDATOR_SIGNING_ENABLED=\"${WEALL_VALIDATOR_SIGNING_ENABLED:-0}\"" in onboarding
    assert "WEALL_HELPER_MODE_ENABLED=\"${WEALL_HELPER_MODE_ENABLED:-0}\"" in onboarding
    assert "WEALL_NODE_LIFECYCLE_STATE=\"${WEALL_NODE_LIFECYCLE_STATE:-production_service}\"" in service
    assert "WEALL_SERVICE_ROLES=\"${WEALL_SERVICE_ROLES:-node_operator}\"" in service
    assert "WEALL_BOUND_ACCOUNT" in service
    assert "WEALL_NODE_PRIVKEY_FILE" in service
    assert "weall_node_key" in node_keys
    assert "not your WeAll account recovery key" in node_keys
    assert "Onboarding node = safe way to join and verify" in doc
