from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent

DOCS_TO_CHECK = [
    ROOT / "docs" / "NEW_NODE_OPERATOR_QUICKSTART.md",
    ROOT / "docs" / "NODE_OPERATOR_ONBOARDING.md",
    ROOT / "docs" / "PRODUCTION_RUNBOOK_VALIDATORS.md",
    ROOT / "docs" / "THREAT_MODEL_CHECKLIST.md",
    ROOT / "docs" / "PRODUCTION_POSTURE.md",
    OUTER / "README.md",
]
FRONTEND_TO_CHECK = [
    OUTER / "web" / "src" / "pages" / "Account.tsx",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_threat_model_uses_separate_node_key_file() -> None:
    text = _read(ROOT / "docs" / "THREAT_MODEL_CHECKLIST.md")
    assert "WEALL_NODE_PRIVKEY_FILE=/secure/path/weall-node.key" in text
    assert "Do **not** use the account recovery key as the node key" in text
    assert "WEALL_NODE_PRIVKEY=<matching Ed25519 seed>" not in text
    assert "WEALL_NODE_PUBKEY=<account active pubkey>" not in text


def test_legacy_onboarding_doc_redirects_to_current_operator_quickstart() -> None:
    text = _read(ROOT / "docs" / "NODE_OPERATOR_ONBOARDING.md")
    assert "superseded by the current first-run operator guide" in text
    assert "docs/NEW_NODE_OPERATOR_QUICKSTART.md" in text
    assert "observer/onboarding node" in text
    assert "automatically activate baseline Node Operator status" in text
    assert "The node key must be separate from the account recovery key" in text
    assert "Baseline Node Operator status does not automatically grant validator authority" in text
    assert "Baseline Node Operator status does not automatically grant storage allocation authority" in text


def test_validator_runbook_describes_responsibility_not_baseline_power() -> None:
    text = _read(ROOT / "docs" / "PRODUCTION_RUNBOOK_VALIDATORS.md")
    assert "Validator Responsibility Production Runbook" in text
    assert "Baseline Node Operator status alone does not grant validator authority" in text
    assert "validator responsibility/readiness is active" in text
    assert "WEALL_NODE_PRIVKEY_FILE" in text
    assert "node key must be separate from the account recovery key" in text
    assert "WEALL_NODE_PRIVKEY\n" not in text


def test_operator_docs_and_frontend_do_not_reintroduce_unsafe_positive_guidance() -> None:
    forbidden = [
        "WEALL_NODE_PRIVKEY=<account_secret>",
        "WEALL_NODE_PRIVKEY=<localSecretKey>",
        "WEALL_NODE_PRIVKEY=<matching Ed25519 seed>",
        "WEALL_NODE_PUBKEY=<account active pubkey>",
        "account private key as node key",
        "Activate node operator role",
        "Await network approval",
        "Activation pending",
        "governance approval required for baseline Node Operator",
        "declared capacity is allocation authority",
        "declared storage capacity is enough for allocation",
        "baseline Node Operator automatically becomes validator",
        "baseline Node Operator automatically becomes storage provider",
    ]
    for path in DOCS_TO_CHECK + FRONTEND_TO_CHECK:
        if not path.exists():
            continue
        text = _read(path)
        for phrase in forbidden:
            assert phrase not in text, f"forbidden stale guidance in {path}: {phrase}"


def test_operator_smoke_rejects_stale_lifecycle_language() -> None:
    proc = subprocess.run(
        ["sh", str(ROOT / "scripts" / "operator_onboarding_smoke.sh")],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stdout
    assert "[operator-onboarding-smoke] OK" in proc.stdout
