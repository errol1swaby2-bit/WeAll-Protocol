from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return subprocess.run(
        [*args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=45,
    )


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _digest_without_self(payload: dict[str, Any]) -> str:
    material = {k: v for k, v in payload.items() if k != "transcript_digest"}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sample_transcript() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "weall.v1_5.external_cross_machine_replay_transcript",
        "blocker": "AUD-618-P1-003",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "git_tree": "a" * 40,
        "branch": "refactor/executor-module-split",
        "operator_ids": ["external-replay-operator-20260705"],
        "machine_ids": ["external-replay-machine-a-20260705", "external-replay-machine-b-20260705"],
        "machine_isolation": "two_physical_machines",
        "operator_attestation": "external_replay_operator_signed",
        "external_attestation_attached": True,
        "machine_summaries": {
            "external-replay-machine-a-20260705": {
                "replay_consistency_ok": True,
                "fresh_node_replay_sync_ok": True,
            },
            "external-replay-machine-b-20260705": {
                "replay_consistency_ok": True,
                "fresh_node_replay_sync_ok": True,
            },
        },
        "state_root_vectors_sha256": "a" * 64,
        "tx_lifecycle_assurance_sha256": "d" * 64,
        "tx_semantic_assurance_sha256": "e" * 64,
        "tx_contract_map_sha256": "f" * 64,
        "live_lifecycle_digest": "1" * 64,
        "broad_probe_lifecycle_manifest_sha256": "d" * 64,
        "broad_probe_lifecycle_projection_sha256": "2" * 64,
        "broad_probe_reversed_projection_sha256": "2" * 64,
        "broad_probe_hash_seed_render_sha256": {
            "0": "d" * 64,
            "1": "d" * 64,
            "7": "d" * 64,
            "42": "d" * 64,
        },
        "tx_index_hash_by_machine": {
            "external-replay-machine-a-20260705": "b" * 64,
            "external-replay-machine-b-20260705": "b" * 64,
        },
        "state_root_by_machine": {
            "external-replay-machine-a-20260705": "c" * 64,
            "external-replay-machine-b-20260705": "c" * 64,
        },
        "replay_manifest_digest_by_machine": {
            "external-replay-machine-a-20260705": "3" * 64,
            "external-replay-machine-b-20260705": "3" * 64,
        },
        "db_replay_digest_by_machine": {
            "external-replay-machine-a-20260705": "4" * 64,
            "external-replay-machine-b-20260705": "4" * 64,
        },
        "fresh_node_replay_digest_by_machine": {
            "external-replay-machine-a-20260705": "5" * 64,
            "external-replay-machine-b-20260705": "5" * 64,
        },
        "hashseed_results_by_machine": {
            machine: {
                seed: {
                    "ok": True,
                    "tx_count": 236,
                    "successful_apply_count": 236,
                    "successful_admission_count": 236,
                    "lifecycle_runtime_digest": "1" * 64,
                    "determinism_pytest_ok": True,
                }
                for seed in ("1", "7", "31337")
            }
            for machine in (
                "external-replay-machine-a-20260705",
                "external-replay-machine-b-20260705",
            )
        },
        "replay_commands": [
            "bash scripts/capture_external_cross_machine_replay_transcript_v1_5.sh --machine-id external-replay-machine-a-20260705 --operator-id external-replay-operator-20260705 --out-dir evidence/a",
            "bash scripts/capture_external_cross_machine_replay_transcript_v1_5.sh --machine-id external-replay-machine-b-20260705 --operator-id external-replay-operator-20260705 --out-dir evidence/b",
        ],
        "replay_outputs": {
            "machine_a_packet": "machine-a/LOCAL_MACHINE_REPLAY_EVIDENCE.json",
            "machine_b_packet": "machine-b/LOCAL_MACHINE_REPLAY_EVIDENCE.json",
        },
        "same_commit": True,
        "same_vectors": True,
        "state_roots_match": True,
        "tx_index_hash_match": True,
        "per_block_replay_match": True,
        "db_replay_match": True,
        "fresh_node_state_sync_match": True,
        "hashseed_matrix_match": True,
        "broad_probe_match": True,
        "insertion_order_projection_match": True,
        "broad_transition_corpus": "all_236_canonical_lifecycle_vectors",
        "scheduler_order_permutation_vectors": True,
        "helper_serial_equivalence_vectors": True,
        "failed_receipt_replay_vectors": True,
        "external_machine_or_two_physical_machines": True,
        "operator_signatures": ["external-signature-reference-20260705-abcdef"],
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "live_economics": False,
            "automatic_protocol_upgrades": False,
            "production_helper_execution": False,
            "legal_compliance_ready": False,
            "public_storage_provider_market": False,
        },
    }
    payload["transcript_digest"] = _digest_without_self(payload)
    return payload


def test_external_cross_machine_replay_capture_script_is_helpful_and_non_authoritative() -> None:
    script = ROOT / "scripts" / "capture_external_cross_machine_replay_transcript_v1_5.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)
    text = script.read_text(encoding="utf-8")
    for required in [
        "AUD-618-P1-003",
        "does not close AUD-618-P1-003",
        "LOCAL_MACHINE_REPLAY_EVIDENCE.json",
        "same commit and same generated vector artifacts",
        "scripts/replay_consistency_audit.py",
        "scripts/rehearse_fresh_node_replay_sync_v1_5.py",
        "capture_a04_external_determinism_packet_v1_5.py",
        "236-type lifecycle corpus",
        "PYTHONHASHSEED",
        "public_beta_ready",
        "external_review_required_before_closure",
    ]:
        assert required in text

    proc = _run(
        "bash", "scripts/capture_external_cross_machine_replay_transcript_v1_5.sh", "--help"
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Captures one machine's replay evidence packet" in proc.stdout
    assert "does not close AUD-618-P1-003" in proc.stdout


def test_external_cross_machine_replay_docs_and_template_keep_blocker_open() -> None:
    runbook = _read("docs/testnet/EXTERNAL_CROSS_MACHINE_REPLAY_TRANSCRIPT.md")
    readme = _read("docs/proofs/external-cross-machine-replay/2026-07-05/README.md")
    template = _read(
        "docs/proofs/external-cross-machine-replay/2026-07-05/TRANSCRIPT_TEMPLATE.json"
    )
    first_15 = _read("docs/testnet/FIRST_15_MINUTES.md")
    status = _read("docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md")

    for text in [runbook, readme, template, first_15, status]:
        assert "AUD-618-P1-003" in text
    assert "does not close the blocker" in runbook
    assert "Status: TEMPLATE ONLY" in readme
    assert "external_cross_machine_replay_transcript" in template
    assert "same_vectors" in template
    assert "tx_index_hash_match" in template
    assert "public beta readiness" in readme
    assert "only external evidence" in status


def test_external_cross_machine_replay_schema_and_validator_accept_real_shape(
    tmp_path: Path,
) -> None:
    proc = _run(
        sys.executable, "scripts/gen_external_operator_transcript_requirements_v1_5.py", "--check"
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(
        (ROOT / "generated" / "external_operator_transcript_requirements_v1_5.json").read_text(
            encoding="utf-8"
        )
    )
    schemas = payload["schemas"]
    assert "external_cross_machine_replay_transcript" in schemas
    schema = schemas["external_cross_machine_replay_transcript"]
    assert "state_root_by_machine" in schema["required_fields"]
    assert "tx_lifecycle_assurance_sha256" in schema["required_fields"]
    assert "hashseed_results_by_machine" in schema["required_fields"]
    assert schema["required_truths"]["blocker"] == "AUD-618-P1-003"
    assert schema["required_truths"]["broad_probe_match"] is True
    assert schema["required_truths"]["insertion_order_projection_match"] is True
    assert (
        schema["required_truths"]["broad_transition_corpus"]
        == "all_236_canonical_lifecycle_vectors"
    )
    assert payload["public_beta_ready"] is False

    transcript_path = tmp_path / "external-cross-machine-replay-transcript.json"
    transcript_path.write_text(
        json.dumps(_sample_transcript(), indent=2, sort_keys=True), encoding="utf-8"
    )
    validate = _run(
        sys.executable,
        "scripts/validate_external_operator_transcript_v1_5.py",
        "--kind",
        "external_cross_machine_replay_transcript",
        "--strict-release",
        "--path",
        str(transcript_path),
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr


def test_public_beta_and_release_artifacts_reference_external_cross_machine_replay() -> None:
    for script in (
        "gen_release_evidence_manifest_v1_5.py",
        "gen_public_beta_blocker_report_v1_5.py",
    ):
        proc = _run(sys.executable, f"scripts/{script}", "--check")
        assert proc.returncode == 0, proc.stdout + proc.stderr

    report = json.loads(
        (ROOT / "generated" / "public_beta_blocker_report_v1_5.json").read_text(encoding="utf-8")
    )
    blockers = {row["id"]: row for row in report["blockers"]}
    blocker = blockers["AUD-618-P1-003"]
    assert blocker["gate_status"] == "gate_present_external_transcript_required"
    assert blocker["can_be_closed_by_code_only"] is False
    assert "matching tx-index hash transcript" in blocker["remaining_external_evidence"]
    assert report["public_beta_ready"] is False

    manifest = json.loads(
        (ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8")
    )
    gate = manifest["release_evidence_gates"]["external_cross_machine_replay_transcript"]
    assert gate["blocker"] == "AUD-618-P1-003"
    assert gate["required_before_public_beta"] is True
    assert gate["required_before_public_observer_launch"] is True
    assert "capture_external_cross_machine_replay_transcript_v1_5.sh" in gate["capture_script"]


def test_a04_broad_cross_machine_determinism_probe_is_green() -> None:
    proc = _run(
        sys.executable,
        "scripts/a04_cross_machine_determinism_probe_v1_5.py",
        "--json",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["tx_count"] == 236
    assert payload["expected_236_contract_counts"] is True
    assert payload["insertion_order_invariant"] is True
    assert payload["hash_seed_render_match"] is True
    assert set(payload["hash_seed_render_sha256"]) == {"0", "1", "7", "42"}


def test_strict_external_replay_rejects_mismatched_machine_digest(tmp_path: Path) -> None:
    payload = _sample_transcript()
    payload["state_root_by_machine"]["external-replay-machine-b-20260705"] = "9" * 64
    payload["transcript_digest"] = _digest_without_self(payload)
    path = tmp_path / "mismatched-replay.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    proc = _run(
        sys.executable,
        "scripts/validate_external_operator_transcript_v1_5.py",
        "--kind",
        "external_cross_machine_replay_transcript",
        "--strict-release",
        "--path",
        str(path),
    )
    assert proc.returncode == 1
    assert "matching values in state_root_by_machine" in proc.stderr
