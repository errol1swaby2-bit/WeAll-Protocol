"""Bounded genuine four-process ML-DSA quorum preflight for issue #87."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "f1b_four_process_signed_qc_preflight.py"


def test_four_process_signed_qc_preflight_fails_closed_on_missing_proof() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    proof = json.loads(proc.stdout)
    assert proof["ok"] is True
    assert proof["process_count"] == proof["validator_count"] == 4
    assert proof["distinct_process_ids"] is True
    assert proof["distinct_validator_keys"] is True
    assert len(set(proof["public_key_sha256"].values())) == 4
    assert proof["quorum_threshold"] == 3
    assert proof["linked_cryptographically_verified_qc_count"] == 3
    assert proof["structural_three_chain_finalized_block"] == "preflight-block-1"
    assert len(proof["synthetic_blocks"]) == 3
    assert all(len(row["qc_signers"]) == 3 for row in proof["synthetic_blocks"])
    assert proof["two_plus_two_without_qc"] is True
    assert proof["three_of_four_after_partition_rejoin"] is True
    assert proof["duplicate_vote_and_bad_signature_blocked"] is True
    assert proof["on_chain_validator_authorization_proven"] is False
    assert proof["production_transport_proven"] is False
    assert proof["canonical_receipt_finality_proven"] is False
    assert proof["durable_validator_restarts_proven"] is False
    # The coordinator never prints raw signatures or validator private keys.
    assert "private_key" not in proc.stdout
    assert '"sig"' not in proc.stdout


def test_four_process_preflight_has_no_dev_consensus_bypasses() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "WEALL_UNSAFE_DEV" not in source
    assert "WEALL_BFT_ALLOW_QC_LESS_BLOCKS" not in source
    assert 'WEALL_SIGVERIFY": "0' not in source
    assert "from weall.runtime.bft_hotstuff import" in source
    assert "sign_mldsa(" in source
    assert "verify_qc(" in source
