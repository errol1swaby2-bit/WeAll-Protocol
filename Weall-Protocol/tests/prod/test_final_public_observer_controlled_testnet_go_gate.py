from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    full = ROOT / path
    assert full.exists(), f"missing file: {path}"
    return full.read_text(encoding="utf-8")


def test_final_go_gate_artifact_is_fresh_and_conservative() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "final_public_observer_controlled_testnet_go_gate_v1_5.json").read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["repo_package_ready"] is True
    assert payload["real_mldsa_implemented_in_this_environment"] is True
    verdict = payload["go_no_go_verdict"]
    assert verdict["controlled_internal_public_observer_rehearsal_candidate"] == "GO"
    assert verdict["bounded_public_observer_launch_claim"].startswith("NO_GO")
    assert verdict["public_beta_claim"].startswith("NO_GO")
    assert verdict["public_mainnet_claim"].startswith("NO_GO")
    assert verdict["public_validator_bft_claim"].startswith("NO_GO")
    counts = payload["blocker_counts"]
    assert counts["blocker_catalog_count"] == 15
    assert counts["closed_in_repository_count"] == 7
    assert counts["remaining_blocker_count"] == 8
    assert counts["p0_open_count"] == 4
    assert counts["p1_open_count"] == 4
    assert payload["external_evidence_still_required"] is True
    assert payload["external_blockers_still_open"] is True
    for key, value in payload["claim_boundaries"].items():
        assert value is False, key


def test_final_go_gate_docs_exist_and_preserve_non_claims() -> None:
    docs = [
        "docs/reviewer/EVIDENCE_INDEX.md",
        "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
        "docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md",
        "docs/testnet/TESTNET_LAUNCH_CHECKLIST.md",
        "docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md",
    ]
    for rel in docs:
        text = _read(rel).lower()
        assert "controlled internal/public-observer rehearsal candidate" in text
        assert "public beta" in text
        assert "no-go" in text or "no_go" in text
        assert "mainnet" in text
        assert "live economics" in text
        assert "automatic" in text
        assert "production helper" in text


def test_evidence_index_maps_remaining_blockers_to_exact_evidence() -> None:
    text = _read("docs/reviewer/EVIDENCE_INDEX.md")
    expected = {
        "AUD-628-P1-001": "External clean-clone/open-download/state-sync/frontend rendered journey transcript",
        "AUD-618-P1-003": "External/two-machine replay transcript",
        "AUD-618-P1-004": "Real storage/IPFS daemon/operator transcript",
        "AUD-618-P0-001": "Independent controlled validator/operator transcript",
        "AUD-618-P0-002": "Real counsel or controlled legal/compliance attestation",
        "AUD-618-P0-003": "Future executable upgrade staging/rollback proof",
        "AUD-618-P1-005": "Future production helper topology proof",
        "AUD-633-P0-004": "fresh profile-aware post-transition rehearsal evidence",
    }
    for blocker, phrase in expected.items():
        assert blocker in text
        assert phrase in text


def test_public_observer_quickstart_and_launch_checklist_use_final_gate() -> None:
    quickstart = _read("docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md")
    checklist = _read("docs/testnet/TESTNET_LAUNCH_CHECKLIST.md")
    for text in (quickstart, checklist):
        assert "gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check" in text
        assert "public_beta_ready=false" in text or "public beta readiness still blocked" in text
        assert "AUD-628-P1-001" in text
    assert "WEALL_PUBLIC_TESTNET=1" in quickstart
    assert "boot_public_observer_testnet.sh" in quickstart
    assert "npm run typecheck" in checklist
    assert "npm run build" in checklist


def test_release_manifest_tracks_final_go_gate() -> None:
    payload = json.loads((ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8"))
    assert "generated/final_public_observer_controlled_testnet_go_gate_v1_5.json" in payload["tracked_artifacts"]
    gate = payload["release_evidence_gates"]["final_public_observer_controlled_testnet_go_gate"]
    assert gate["controlled_rehearsal_candidate_allowed"] is True
    assert payload["release_evidence_gates"]["post_quantum_signature_profile_transition"]["real_mldsa_required_before_controlled_testnet"] is False
    assert gate["public_beta_ready"] is False
    assert gate["public_observer_launch_claim_ready"] is False


def test_public_readiness_checker_tracks_final_go_gate() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/check_v15_public_readiness_artifacts.py"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
