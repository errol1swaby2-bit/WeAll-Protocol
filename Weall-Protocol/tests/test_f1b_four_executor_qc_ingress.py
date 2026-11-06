"""Four SQLite-backed WeAllExecutor processes with signed BFT QC ingress.

This fixture does not establish on-chain validator admission, actual finality,
network transport or process-restart durability.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "f1b_four_executor_qc_ingress.py"


def test_four_real_executor_processes_form_and_verify_a_signed_qc() -> None:
    process = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=240,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    proof = json.loads(process.stdout)
    assert proof["ok"] is True
    assert proof["scope"] == "four_sqlite_executor_processes_cryptographic_ingress_only"
    assert proof["separate_processes"] == 4
    assert proof["separate_sqlite_databases"] == 4
    assert proof["signing_api"] == "WeAllExecutor.bft_make_vote_for_block"
    assert proof["aggregation_api"] == "WeAllExecutor.bft_on_vote"
    assert proof["qc_verification_api"] == "WeAllExecutor.bft_verify_qc_json"
    assert proof["strict_epoch_binding"] is True
    assert proof["signature_verification_enabled"] is True
    assert proof["qc_less_blocks_allowed"] is False
    assert proof["quorum_threshold"] == 3
    assert proof["verified_on_all_four_executors"] is True
    assert proof["tampered_certificate_variants_rejected"] == 5
    assert proof["two_plus_two_does_not_form_qc"] is True
    assert proof["three_vote_quorum_restored"] is True
    assert proof["validator_set_source"] == "direct_test_fixture"
    assert proof["on_chain_validator_authorization_proven"] is False
    assert proof["real_proposal_admission_proven"] is False
    assert proof["live_transport_proven"] is False
    assert proof["canonical_receipt_finality_proven"] is False
    assert proof["durable_process_restart_proven"] is False
    assert '"sig"' not in process.stdout
    assert "private_key" not in process.stdout


def test_executor_preflight_keeps_consensus_bypasses_disabled() -> None:
    content = SCRIPT.read_text(encoding="utf-8")
    for exact in (
        '"WEALL_SIGVERIFY": "1"',
        '"WEALL_UNSAFE_DEV": "0"',
        '"WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "0"',
        '"WEALL_BFT_STRICT_EPOCH_BINDING": "1"',
    ):
        assert exact in content
    assert ".bft_make_vote_for_block(" in content
    assert ".bft_on_vote(" in content
    assert ".bft_verify_qc_json(" in content
