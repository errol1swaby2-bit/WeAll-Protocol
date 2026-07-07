from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_PAGE = ROOT / "web" / "src" / "pages" / "Account.tsx"


def test_node_operator_ui_does_not_offer_self_activation() -> None:
    text = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "ROLE_NODE_OPERATOR_ENROLL" in text
    assert "Submit node operator enrollment" in text
    assert "Enrollment submitted" in text
    assert "Checking eligibility" in text
    assert "automatically activates baseline Node Operator status" in text
    assert "ROLE_NODE_OPERATOR_ACTIVATE" not in text
    assert "Activate node operator role" not in text
    assert "runOperatorTx(\"activate\")" not in text
    assert "Activating…" not in text


def test_node_operator_checklist_separates_enrollment_from_activation() -> None:
    text = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "Node operator enrollment submitted" in text
    assert "Node Operator status active" in text
    assert "Waiting for eligibility" in text
    assert "Checking eligibility" in text
    assert "Validator and storage responsibilities are optional opt-in responsibilities" in text


def test_node_operator_ready_requires_active_role() -> None:
    text = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "const nodeOperatorEnrolled" in text
    assert "const nodeOperatorActive" in text
    assert "const nodeDeviceReady" in text
    assert "const operatorReady = nodeDeviceReady && nodeOperatorActive" in text
