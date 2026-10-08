from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build_external_cross_machine_replay_transcript_v1_5.py"
CAPTURE = ROOT / "scripts" / "capture_a04_external_determinism_packet_v1_5.py"
WRAPPER = ROOT / "scripts" / "capture_external_cross_machine_replay_transcript_v1_5.sh"


def _load_builder():
    spec = importlib.util.spec_from_file_location("a04_builder_testmod", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _packet(machine_id: str) -> dict:
    seed_results = {
        seed: {
            "ok": True,
            "tx_count": 236,
            "successful_apply_count": 236,
            "successful_admission_count": 236,
            "lifecycle_runtime_digest": "a" * 64,
            "determinism_pytest_ok": True,
        }
        for seed in ("1", "7", "31337")
    }
    return {
        "schema": "weall.v1_5.external_cross_machine_replay_local_packet",
        "blocker": "AUD-618-P1-003",
        "a04_f002_scope": True,
        "machine_id": machine_id,
        "operator_id": "independent-operator",
        "commit": "1" * 40,
        "git_tree": "2" * 40,
        "branch": "p2-revalidation-after-p1-20261007",
        "git_status_short": "",
        "python": "3.12.14",
        "platform": "test-platform",
        "state_root_vectors_sha256": "3" * 64,
        "tx_index_sha256": "4" * 64,
        "tx_contract_map_sha256": "5" * 64,
        "tx_lifecycle_assurance_sha256": "6" * 64,
        "tx_semantic_assurance_sha256": "7" * 64,
        "broad_probe_ok": True,
        "broad_probe_lifecycle_manifest_sha256": "6" * 64,
        "broad_probe_lifecycle_projection_sha256": "e" * 64,
        "broad_probe_reversed_projection_sha256": "e" * 64,
        "broad_probe_insertion_order_invariant": True,
        "broad_probe_hash_seed_render_match": True,
        "broad_probe_hash_seed_render_sha256": {
            "0": "6" * 64,
            "1": "6" * 64,
            "7": "6" * 64,
            "42": "6" * 64,
        },
        "replay_consistency_ok": True,
        "fresh_node_replay_sync_ok": True,
        "db_backed_replay_sync_ok": True,
        "broad_lifecycle_corpus_ok": True,
        "scheduler_order_permutation_ok": True,
        "helper_serial_equivalence_ok": True,
        "failed_receipt_replay_ok": True,
        "hashseed_results": seed_results,
        "replay_manifest_digest": "8" * 64,
        "db_replay_digest": "9" * 64,
        "fresh_node_replay_digest": "b" * 64,
        "state_root": "c" * 64,
        "fresh_state_root": "d" * 64,
        "interrupted_resume_root": "d" * 64,
        "capture_command": f"capture {machine_id}",
        "public_beta_ready": False,
        "mainnet_ready": False,
        "external_review_required_before_closure": True,
    }


def _write_packet(path: Path, payload: dict) -> Path:
    import json

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def test_a04_aggregate_builder_accepts_two_matching_strict_packets(tmp_path: Path) -> None:
    module = _load_builder()
    a = _write_packet(tmp_path / "a.json", _packet("machine-a"))
    b = _write_packet(tmp_path / "b.json", _packet("machine-b"))

    transcript = module.build_transcript(
        [a, b],
        machine_isolation="two_physical_machines",
        operator_attestation="external_replay_operator_signed",
        operator_signatures=["controlled-signature-reference-1234567890"],
    )

    assert transcript["same_commit"] is True
    assert transcript["same_vectors"] is True
    assert transcript["state_roots_match"] is True
    assert transcript["per_block_replay_match"] is True
    assert transcript["hashseed_matrix_match"] is True
    assert transcript["broad_probe_match"] is True
    assert transcript["insertion_order_projection_match"] is True
    assert transcript["broad_probe_lifecycle_manifest_sha256"] == "6" * 64
    assert transcript["broad_transition_corpus"] == "all_236_canonical_lifecycle_vectors"
    assert transcript["scheduler_order_permutation_vectors"] is True
    assert transcript["helper_serial_equivalence_vectors"] is True
    assert transcript["failed_receipt_replay_vectors"] is True
    assert transcript["git_tree"] == "2" * 40
    assert len(transcript["machine_ids"]) == 2
    assert len(transcript["transcript_digest"]) == 64


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("commit", "f" * 40),
        ("git_tree", "e" * 40),
        ("tx_index_sha256", "d" * 64),
        ("tx_lifecycle_assurance_sha256", "c" * 64),
        ("replay_manifest_digest", "1" * 64),
        ("db_replay_digest", "2" * 64),
        ("fresh_node_replay_digest", "3" * 64),
        ("state_root", "4" * 64),
    ],
)
def test_a04_aggregate_builder_rejects_cross_machine_mismatch(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    module = _load_builder()
    first = _packet("machine-a")
    second = _packet("machine-b")
    second[field] = replacement
    a = _write_packet(tmp_path / "a.json", first)
    b = _write_packet(tmp_path / "b.json", second)

    with pytest.raises(ValueError):
        module.build_transcript(
            [a, b],
            machine_isolation="two_physical_machines",
            operator_attestation="external_replay_operator_signed",
            operator_signatures=["controlled-signature-reference-1234567890"],
        )


def test_a04_packet_rejects_hashseed_instability(tmp_path: Path) -> None:
    module = _load_builder()
    first = _packet("machine-a")
    second = _packet("machine-b")
    second["hashseed_results"]["31337"]["lifecycle_runtime_digest"] = "f" * 64
    a = _write_packet(tmp_path / "a.json", first)
    b = _write_packet(tmp_path / "b.json", second)

    with pytest.raises(ValueError, match="PYTHONHASHSEED|lifecycle"):
        module.build_transcript(
            [a, b],
            machine_isolation="two_physical_machines",
            operator_attestation="external_replay_operator_signed",
            operator_signatures=["controlled-signature-reference-1234567890"],
        )


def test_a04_capture_runner_covers_original_audit_evidence_classes() -> None:
    capture = CAPTURE.read_text(encoding="utf-8")
    wrapper = WRAPPER.read_text(encoding="utf-8")

    for required in (
        'SEEDS = ("1", "7", "31337")',
        "gen_tx_lifecycle_assurance_v1_5.py",
        "replay_consistency_audit.py",
        "rehearse_fresh_node_replay_sync_v1_5.py",
        "rehearse_db_backed_fresh_node_replay_sync_v1_5.py",
        "test_p0_scheduler_and_receipt_breadth_closure.py",
        "test_helper_serial_equivalence_corpus.py",
        "test_nonce_failure_block_progression.py",
        "test_p2_a02_success_lifecycle_baseline.py",
        "test_p2_a02_lifecycle_manifest.py",
        "git_status_short",
        "git_tree",
        "hashseed_results",
        "a04_cross_machine_determinism_probe_v1_5.py",
        "broad_probe_ok",
        "broad_probe_insertion_order_invariant",
        "broad_probe_hash_seed_render_match",
        "broad_lifecycle_corpus_ok",
        "scheduler_order_permutation_ok",
        "helper_serial_equivalence_ok",
        "failed_receipt_replay_ok",
    ):
        assert required in capture

    assert "two external/physical machines" in wrapper
    assert "build_external_cross_machine_replay_transcript_v1_5.py" in wrapper
    assert "--strict-release" in wrapper
