from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_pending_tx_semantic_reviews.py"
REVIEWS = ROOT / "specs" / "v2" / "source" / "semantic_reviews.json"


def test_pending_semantic_report_is_review_only_and_deterministic(tmp_path: Path) -> None:
    before = REVIEWS.read_bytes()
    destination = tmp_path / "semantic_review_candidates.json"
    subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(destination)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    first = destination.read_bytes()
    subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(destination)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert destination.read_bytes() == first
    assert REVIEWS.read_bytes() == before

    report = json.loads(first)
    assert report["authority"] == "diagnostic_only_not_a_review_attestation"
    assert report["changes_accepted"] is False
    assert len(report["transactions"]) == 7
    assert {row["tx_type"] for row in report["transactions"]} == {
        "ACCOUNT_REGISTER",
        "BALANCE_TRANSFER",
        "BLOCK_REWARD_DISTRIBUTE",
        "CREATOR_REWARD_ALLOCATE",
        "FEE_PAY",
        "FORFEITURE_APPLY",
        "TREASURY_REWARD_ALLOCATE",
    }
    for row in report["transactions"]:
        assert re.fullmatch(r"[0-9a-f]{64}", row["candidate_digest"])
        assert row["independent_review_completed"] is False
        assert row["acceptance_status"] in {
            "PENDING_MAINTAINER_REVIEW",
            "PREVIOUS_DIGEST_MATCHES",
        }
        assert row["candidate_differs_from_accepted"] == (
            row["candidate_digest"] != row["previous_accepted_digest"]
        )
        assert row["material_for_review"]["tx_type"] == row["tx_type"]
