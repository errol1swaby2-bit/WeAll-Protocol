from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def _read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def test_status_exposes_production_readiness_blockers_batch456() -> None:
    status = _read("Weall-Protocol/src/weall/api/routes_public_parts/status.py")
    assert '"block_production"' in status
    assert '"tokenomics"' in status
    assert '"p2p_encrypted_messaging"' in status
    assert "public multi-validator BFT is not claimed" in status
    assert "metadata remains visible" in status


def test_reviewer_gate_and_ci_are_tracked_batch456() -> None:
    gate = _read("Weall-Protocol/scripts/reviewer_production_readiness_gate.sh")
    workflow = _read(".github/workflows/reviewer-readiness.yml")
    assert "scripts/check_tx_canon_artifacts.py" in gate
    assert "scripts/secret_guard.sh" in gate
    assert "scripts/verify_release_tree.sh" in gate
    assert "tests/test_batch456_production_readiness_and_p2p_e2ee_gates.py" in gate
    assert "Run reviewer readiness gate" in workflow
    assert "reviewer_production_readiness_gate.sh" in workflow


def test_docs_do_not_overclaim_tokenomics_or_e2ee_batch456() -> None:
    gap = _read("Weall-Protocol/docs/PRODUCTION_ORIENTED_REHEARSAL_GAP_AUDIT.md")
    econ = _read("Weall-Protocol/docs/ECONOMICS_LOCKED_TOKENOMICS_MODEL.md")
    msg = _read("Weall-Protocol/docs/P2P_ENCRYPTED_MESSAGING_PRODUCTION_GATE.md")
    milestone = _read("Weall-Protocol/docs/REVIEWER_PRODUCTION_READINESS_MILESTONE.md")

    assert "not yet safe" in gap
    assert "block production proof truth boundary" in gap
    assert "locked Genesis model" in econ
    assert "Permanently fee-free" in econ
    assert "not final production P2P private messaging" in msg
    assert "ratchet/forward-secrecy" in msg
    assert "not as a finished public mainnet" in milestone
