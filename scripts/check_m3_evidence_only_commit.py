#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from m3_evidence_contract import (
    ACTOR_MANIFEST_PATH,
    ARTIFACT_ROOT,
    LIVE_BALLOT_PROFILE_PATH,
    MILESTONE,
    OBSERVER_AUTHORITY_PATH,
    PRIVACY_REPORT_PATH,
    REQUIRED_ACTION_LABELS,
    REQUIRED_EXACT_PATHS,
    REQUIRED_GATES,
    REQUIRED_NEGATIVE_LABELS,
    REQUIRED_PREFIXES,
    STATE_SUMMARY_PATHS,
    TRANSACTION_TRANSCRIPT_PATH,
    TRUTH_BOUNDARY,
    private_material_findings,
    validate_observer_authority,
    validate_live_ballot_profile,
    validate_public_actor_transcript,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = f"{ARTIFACT_ROOT}/M3_EVIDENCE_MANIFEST.json"
MANIFEST_KEYS = {
    "schema_version",
    "milestone",
    "generated_at_utc",
    "mode",
    "implementation_freeze_commit",
    "implementation_tree",
    "evidence_commit_parent_required",
    "artifact_root",
    "artifact_count",
    "all_gates_passed",
    "gates",
    "files",
    "journey_summary",
    "final_state_roots",
    "observer_authority",
    "live_ballot_profile",
    "transcript_hashes",
    "private_material_scan",
    "truth_boundary",
}


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def git_bytes(spec: str) -> bytes:
    return subprocess.check_output(["git", "show", spec], cwd=ROOT)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"m3_evidence_invalid_json:{label}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"m3_evidence_json_not_object:{label}")
    return value


def changed_paths(mode: str, commit: str) -> list[str]:
    if mode == "staged":
        raw = run("git", "diff", "--cached", "--name-status", "--diff-filter=ACMRD")
    else:
        raw = run("git", "diff-tree", "--no-commit-id", "--name-status", "-r", commit)
    paths: list[str] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status[:1] not in {"A", "M"}:
            raise SystemExit(f"m3_evidence_change_type_forbidden:{status}:{parts[-1]}")
        paths.append(parts[-1])
    return sorted(set(paths))


def _validate_state_summary(value: dict[str, Any], *, label: str, freeze: str, tree: str) -> dict[str, Any]:
    if value.get("schema_version") != 2 or value.get("equal") is not True:
        raise SystemExit(f"m3_state_summary_invalid:{label}")
    if value.get("implementation_freeze_commit") != freeze or value.get("implementation_tree") != tree:
        raise SystemExit(f"m3_state_summary_freeze_mismatch:{label}")
    if value.get("distinct_processes") is not True or value.get("distinct_datastores") is not True:
        raise SystemExit(f"m3_state_summary_independence_missing:{label}")
    nodes = value.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 2:
        raise SystemExit(f"m3_state_summary_nodes_invalid:{label}")
    node_ids = {str(item.get("node_id") or "") for item in nodes if isinstance(item, dict)}
    if len(node_ids) != 2 or "" in node_ids:
        raise SystemExit(f"m3_state_summary_node_ids_invalid:{label}")
    final = value.get("final")
    if not isinstance(final, dict):
        raise SystemExit(f"m3_state_summary_final_missing:{label}")
    for field in ("chain_id", "height", "tip_hash", "state_root", "tx_index_hash", "protocol_profile_hash"):
        if final.get(field) in (None, ""):
            raise SystemExit(f"m3_state_summary_field_missing:{label}:{field}")
    if label == "observer":
        authority = value.get("observer_authority")
        if not isinstance(authority, dict) or authority.get("observer_mode") is not True:
            raise SystemExit("m3_observer_authority_summary_missing")
        for field in ("validator_signing_enabled", "bft_signing_authority", "helper_authority", "treasury_or_governance_authority"):
            if authority.get(field) is not False:
                raise SystemExit(f"m3_observer_authority_not_false:{field}")
    return final


def _validate_actor_and_transcript(actor: dict[str, Any], transcript: dict[str, Any], *, freeze: str) -> dict[str, Any]:
    try:
        return validate_public_actor_transcript(actor, transcript, freeze=freeze)
    except ValueError as exc:
        raise SystemExit(f"m3_actor_transcript_contract_invalid:{exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("staged", "commit"), required=True)
    parser.add_argument("--freeze-commit", required=True)
    parser.add_argument("--commit", default="HEAD")
    args = parser.parse_args()

    freeze = run("git", "rev-parse", f"{args.freeze_commit}^{{commit}}")
    freeze_tree = run("git", "rev-parse", f"{freeze}^{{tree}}")
    if run("git", "ls-tree", "-r", "--name-only", freeze, "--", ARTIFACT_ROOT):
        raise SystemExit("m3_evidence_inherited_from_freeze")

    commit = run("git", "rev-parse", f"{args.commit}^{{commit}}") if args.mode == "commit" else ""
    if args.mode == "staged":
        if run("git", "rev-parse", "HEAD") != freeze:
            raise SystemExit("m3_evidence_staged_head_not_freeze")
    elif run("git", "rev-parse", f"{commit}^") != freeze:
        raise SystemExit("m3_evidence_commit_not_direct_child")

    paths = changed_paths(args.mode, commit)
    if not paths or MANIFEST_PATH not in paths:
        raise SystemExit("m3_evidence_manifest_or_paths_missing")
    for path in paths:
        if not path.startswith(f"{ARTIFACT_ROOT}/"):
            raise SystemExit(f"m3_evidence_non_evidence_path:{path}")

    def read(path: str) -> bytes:
        spec = f":{path}" if args.mode == "staged" else f"{commit}:{path}"
        try:
            return git_bytes(spec)
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"m3_evidence_blob_missing:{path}") from exc

    manifest_bytes = read(MANIFEST_PATH)
    if private_material_findings(manifest_bytes):
        raise SystemExit("m3_evidence_private_material:manifest")
    manifest = parse_json(manifest_bytes, MANIFEST_PATH)
    if set(manifest) != MANIFEST_KEYS:
        raise SystemExit("m3_evidence_manifest_top_level_keys_mismatch")
    if manifest.get("schema_version") != 3:
        raise SystemExit("m3_evidence_manifest_schema_mismatch")
    if manifest.get("milestone") != MILESTONE or manifest.get("truth_boundary") != TRUTH_BOUNDARY:
        raise SystemExit("m3_evidence_manifest_truth_boundary_mismatch")
    if manifest.get("implementation_freeze_commit") != freeze or manifest.get("implementation_tree") != freeze_tree:
        raise SystemExit("m3_evidence_manifest_freeze_mismatch")
    if manifest.get("evidence_commit_parent_required") != freeze:
        raise SystemExit("m3_evidence_manifest_parent_mismatch")
    if manifest.get("artifact_root") != ARTIFACT_ROOT:
        raise SystemExit("m3_evidence_manifest_root_mismatch")
    if manifest.get("all_gates_passed") is not True or manifest.get("private_material_scan") != "passed":
        raise SystemExit("m3_evidence_manifest_not_closed")

    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("artifact_count") != len(files):
        raise SystemExit("m3_evidence_manifest_file_count_mismatch")
    entries: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
            raise SystemExit("m3_evidence_manifest_file_entry_invalid")
        path = str(item.get("path") or "")
        if not path.startswith(f"{ARTIFACT_ROOT}/") or path == MANIFEST_PATH or path in entries:
            raise SystemExit(f"m3_evidence_manifest_bad_path:{path}")
        entries[path] = item

    committed = set(paths) - {MANIFEST_PATH}
    if set(entries) != committed:
        raise SystemExit(
            "m3_evidence_manifest_path_set_mismatch:"
            + json.dumps({"missing_from_manifest": sorted(committed - set(entries)), "not_in_commit": sorted(set(entries) - committed)}, sort_keys=True)
        )
    for prefix in REQUIRED_PREFIXES:
        if not any(path.startswith(prefix) for path in entries):
            raise SystemExit(f"m3_evidence_required_prefix_missing:{prefix}")
    for required in REQUIRED_EXACT_PATHS:
        if required not in entries:
            raise SystemExit(f"m3_evidence_required_artifact_missing:{required}")

    blobs: dict[str, bytes] = {}
    for path, item in entries.items():
        data = read(path)
        blobs[path] = data
        if item.get("size_bytes") != len(data) or item.get("sha256") != digest(data):
            raise SystemExit(f"m3_evidence_file_binding_mismatch:{path}")
        findings = private_material_findings(data)
        if findings:
            raise SystemExit(f"m3_evidence_private_material:{path}:{findings}")

    gates = manifest.get("gates")
    if not isinstance(gates, list):
        raise SystemExit("m3_evidence_gates_missing")
    by_gate: dict[str, dict[str, Any]] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            raise SystemExit("m3_evidence_gate_invalid")
        name = str(gate.get("gate") or "")
        if not name or name in by_gate:
            raise SystemExit(f"m3_evidence_gate_duplicate_or_blank:{name}")
        if gate.get("status") != "passed" or int(gate.get("exit_code") if gate.get("exit_code") is not None else -1) != 0:
            raise SystemExit(f"m3_evidence_gate_not_passed:{name}")
        log = str(gate.get("log") or "")
        if log not in entries:
            raise SystemExit(f"m3_evidence_gate_log_missing:{name}:{log}")
        if gate.get("log_sha256") != entries[log]["sha256"] or gate.get("log_size_bytes") != entries[log]["size_bytes"]:
            raise SystemExit(f"m3_evidence_gate_log_binding_mismatch:{name}")
        by_gate[name] = gate
    if set(by_gate) != set(REQUIRED_GATES):
        raise SystemExit(
            "m3_evidence_gate_set_mismatch:"
            + json.dumps({"missing": sorted(set(REQUIRED_GATES) - set(by_gate)), "unexpected": sorted(set(by_gate) - set(REQUIRED_GATES))}, sort_keys=True)
        )

    actor = parse_json(blobs[ACTOR_MANIFEST_PATH], ACTOR_MANIFEST_PATH)
    transcript = parse_json(blobs[TRANSACTION_TRANSCRIPT_PATH], TRANSACTION_TRANSCRIPT_PATH)
    expected_journey = _validate_actor_and_transcript(actor, transcript, freeze=freeze)
    if manifest.get("journey_summary") != expected_journey:
        raise SystemExit("m3_evidence_journey_summary_mismatch")

    expected_roots: dict[str, Any] = {}
    for label, path in STATE_SUMMARY_PATHS.items():
        expected_roots[label] = _validate_state_summary(parse_json(blobs[path], path), label=label, freeze=freeze, tree=freeze_tree)
    if manifest.get("final_state_roots") != expected_roots:
        raise SystemExit("m3_evidence_final_state_roots_mismatch")

    try:
        expected_observer_authority = validate_observer_authority(
            parse_json(blobs[OBSERVER_AUTHORITY_PATH], OBSERVER_AUTHORITY_PATH),
            freeze=freeze,
            tree=freeze_tree,
        )
    except ValueError as exc:
        raise SystemExit(f"m3_observer_authority_contract_invalid:{exc}") from exc
    if manifest.get("observer_authority") != expected_observer_authority:
        raise SystemExit("m3_evidence_observer_authority_mismatch")

    try:
        expected_live_ballot_profile = validate_live_ballot_profile(
            parse_json(blobs[LIVE_BALLOT_PROFILE_PATH], LIVE_BALLOT_PROFILE_PATH),
            freeze=freeze,
            tree=freeze_tree,
        )
    except ValueError as exc:
        raise SystemExit(f"m3_live_ballot_profile_contract_invalid:{exc}") from exc
    if manifest.get("live_ballot_profile") != expected_live_ballot_profile:
        raise SystemExit("m3_evidence_live_ballot_profile_mismatch")

    expected_transcript_hashes = {
        TRANSACTION_TRANSCRIPT_PATH: digest(blobs[TRANSACTION_TRANSCRIPT_PATH]),
        LIVE_BALLOT_PROFILE_PATH: digest(blobs[LIVE_BALLOT_PROFILE_PATH]),
        **{path: digest(blobs[path]) for path in STATE_SUMMARY_PATHS.values()},
    }
    if manifest.get("transcript_hashes") != expected_transcript_hashes:
        raise SystemExit("m3_evidence_transcript_hashes_mismatch")

    privacy = parse_json(blobs[PRIVACY_REPORT_PATH], PRIVACY_REPORT_PATH)
    if privacy.get("ok") is not True or privacy.get("violations") != []:
        raise SystemExit("m3_evidence_privacy_report_not_clean")

    print(f"OK: M3 evidence-only commit verified {len(entries)} artifacts and {len(by_gate)} mandatory gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
