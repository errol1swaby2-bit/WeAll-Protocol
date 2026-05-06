from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_PAGE = ROOT / "web" / "src" / "pages" / "Account.tsx"


def test_node_operator_ui_does_not_offer_self_activation_batch290() -> None:
    text = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "ROLE_NODE_OPERATOR_ENROLL" in text
    assert "Submit node operator enrollment" in text
    assert "Enrollment submitted" in text
    assert "Awaiting network approval" in text
    assert "Network approval is required" in text
    assert "ROLE_NODE_OPERATOR_ACTIVATE" not in text
    assert "Activate node operator role" not in text
    assert "runOperatorTx(\"activate\")" not in text
    assert "Activating…" not in text


def test_node_operator_checklist_separates_enrollment_from_activation_batch290() -> None:
    text = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "Node operator enrollment submitted" in text
    assert "Network activation approved" in text
    assert "Wait for activation" in text
    assert "Activation pending" in text
    assert "activation is approved by" in text or "activation is governance" in text


def test_node_operator_ready_requires_active_role_batch290() -> None:
    text = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "const nodeOperatorEnrolled" in text
    assert "const nodeOperatorActive" in text
    assert "const nodeDeviceReady" in text
    assert "const operatorReady = nodeDeviceReady && nodeOperatorActive" in text
