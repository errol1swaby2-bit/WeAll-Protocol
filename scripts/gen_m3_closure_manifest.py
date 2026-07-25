#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(args: list[str], cwd: Path, *, required: bool = False) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if required and result.returncode != 0:
        raise SystemExit(f"m3_manifest_git_failure:{' '.join(args)}:{result.stderr.strip()}")
    return result.stdout.strip() if result.returncode == 0 else ""


def scan_private_material(path: Path) -> None:
    findings = private_material_findings(path.read_bytes())
    if findings:
        raise SystemExit(f"m3_evidence_contains_private_material:{path}:{findings}")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"m3_manifest_invalid_json:{label}:{path}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"m3_manifest_not_object:{label}:{path}")
    return value


def parse_results(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t", 4)
        if len(parts) != 5:
            raise SystemExit(f"m3_results_invalid_row:{raw_line}")
        name, status, code, log_name, command = parts
        if status not in {"passed", "failed"}:
            raise SystemExit(f"m3_results_invalid_status:{name}:{status}")
        rows.append({"gate": name, "status": status, "exit_code": int(code), "log": log_name, "command": command})
    if not rows:
        raise SystemExit("m3_results_empty")
    names = [str(row["gate"]) for row in rows]
    if len(names) != len(set(names)):
        raise SystemExit("m3_results_duplicate_gate")
    if set(names) != set(REQUIRED_GATES):
        raise SystemExit(
            "m3_results_gate_set_mismatch:"
            + json.dumps({"missing": sorted(set(REQUIRED_GATES) - set(names)), "unexpected": sorted(set(names) - set(REQUIRED_GATES))}, sort_keys=True)
        )
    return rows


def validate_state_summary(value: dict[str, Any], *, label: str, freeze: str, tree: str) -> dict[str, Any]:
    if value.get("schema_version") != 2 or value.get("equal") is not True:
        raise SystemExit(f"m3_state_summary_invalid:{label}")
    if value.get("implementation_freeze_commit") != freeze or value.get("implementation_tree") != tree:
        raise SystemExit(f"m3_state_summary_freeze_mismatch:{label}")
    if value.get("distinct_processes") is not True or value.get("distinct_datastores") is not True:
        raise SystemExit(f"m3_state_summary_independence_missing:{label}")
    nodes = value.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 2:
        raise SystemExit(f"m3_state_summary_nodes_invalid:{label}")
    node_ids = {str(node.get("node_id") or "") for node in nodes if isinstance(node, dict)}
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


def validate_actor_and_transcript(actor: dict[str, Any], transcript: dict[str, Any], *, freeze: str) -> dict[str, Any]:
    try:
        return validate_public_actor_transcript(actor, transcript, freeze=freeze)
    except ValueError as exc:
        raise SystemExit(f"m3_actor_transcript_contract_invalid:{exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--mode", default="evidence-generation")
    parser.add_argument("--implementation-freeze", default=os.environ.get("M3_IMPLEMENTATION_FREEZE_COMMIT", ""))
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    evidence = Path(args.evidence_dir).resolve()
    results_path = Path(args.results).resolve()
    if evidence.relative_to(workspace).as_posix() != ARTIFACT_ROOT:
        raise SystemExit("m3_evidence_dir_must_equal_canonical_root")
    if not evidence.is_dir() or not results_path.is_file():
        raise SystemExit("m3_evidence_inputs_missing")

    freeze_raw = str(args.implementation_freeze or "").strip()
    if not freeze_raw:
        raise SystemExit("M3 implementation freeze commit is required")
    freeze = git(["rev-parse", f"{freeze_raw}^{{commit}}"], workspace, required=True)
    freeze_tree = git(["rev-parse", f"{freeze}^{{tree}}"], workspace, required=True)
    if git(["rev-parse", "HEAD"], workspace, required=True) != freeze:
        raise SystemExit("m3_manifest_generation_head_not_freeze")

    rows = parse_results(results_path)
    out = evidence / "M3_EVIDENCE_MANIFEST.json"
    files: list[dict[str, Any]] = []
    for path in sorted(evidence.rglob("*")):
        if not path.is_file() or path.resolve() == out.resolve():
            continue
        if path.is_symlink():
            raise SystemExit(f"m3_evidence_symlink_forbidden:{path}")
        scan_private_material(path)
        files.append({"path": path.relative_to(workspace).as_posix(), "sha256": sha256(path), "size_bytes": path.stat().st_size})
    if not files:
        raise SystemExit("m3_evidence_manifest_has_no_artifacts")
    by_path = {str(item["path"]): item for item in files}
    for prefix in REQUIRED_PREFIXES:
        if not any(path.startswith(prefix) for path in by_path):
            raise SystemExit(f"m3_evidence_required_prefix_missing:{prefix}")
    for required in REQUIRED_EXACT_PATHS:
        if required not in by_path:
            raise SystemExit(f"m3_evidence_required_artifact_missing:{required}")

    for row in rows:
        log_path = evidence / str(row["log"])
        if not log_path.is_file():
            raise SystemExit(f"m3_gate_log_missing:{row['gate']}:{row['log']}")
        rel_log = log_path.relative_to(workspace).as_posix()
        item = by_path.get(rel_log)
        if item is None:
            raise SystemExit(f"m3_gate_log_not_bound:{row['gate']}")
        row["log"] = rel_log
        row["log_sha256"] = item["sha256"]
        row["log_size_bytes"] = item["size_bytes"]

    actor = load_json(workspace / ACTOR_MANIFEST_PATH, "actor_manifest")
    transcript = load_json(workspace / TRANSACTION_TRANSCRIPT_PATH, "transaction_transcript")
    journey_summary = validate_actor_and_transcript(actor, transcript, freeze=freeze)

    final_state_roots: dict[str, Any] = {}
    for label, rel in STATE_SUMMARY_PATHS.items():
        value = load_json(workspace / rel, label)
        final_state_roots[label] = validate_state_summary(value, label=label, freeze=freeze, tree=freeze_tree)

    observer_authority_raw = load_json(workspace / OBSERVER_AUTHORITY_PATH, "observer_authority")
    try:
        observer_authority = validate_observer_authority(observer_authority_raw, freeze=freeze, tree=freeze_tree)
    except ValueError as exc:
        raise SystemExit(f"m3_observer_authority_contract_invalid:{exc}") from exc

    live_profile_raw = load_json(workspace / LIVE_BALLOT_PROFILE_PATH, "live_ballot_profile")
    try:
        live_ballot_profile = validate_live_ballot_profile(
            live_profile_raw,
            freeze=freeze,
            tree=freeze_tree,
        )
    except ValueError as exc:
        raise SystemExit(f"m3_live_ballot_profile_contract_invalid:{exc}") from exc

    privacy = load_json(workspace / PRIVACY_REPORT_PATH, "privacy_report")
    if privacy.get("ok") is not True or privacy.get("violations") != []:
        raise SystemExit("m3_privacy_report_not_clean")

    manifest = {
        "schema_version": 3,
        "milestone": MILESTONE,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": str(args.mode),
        "implementation_freeze_commit": freeze,
        "implementation_tree": freeze_tree,
        "evidence_commit_parent_required": freeze,
        "artifact_root": ARTIFACT_ROOT,
        "artifact_count": len(files),
        "all_gates_passed": all(row["status"] == "passed" and row["exit_code"] == 0 for row in rows),
        "gates": rows,
        "files": files,
        "journey_summary": journey_summary,
        "final_state_roots": final_state_roots,
        "observer_authority": observer_authority,
        "live_ballot_profile": live_ballot_profile,
        "transcript_hashes": {
            TRANSACTION_TRANSCRIPT_PATH: by_path[TRANSACTION_TRANSCRIPT_PATH]["sha256"],
            LIVE_BALLOT_PROFILE_PATH: by_path[LIVE_BALLOT_PROFILE_PATH]["sha256"],
            **{rel: by_path[rel]["sha256"] for rel in STATE_SUMMARY_PATHS.values()},
        },
        "private_material_scan": "passed",
        "truth_boundary": TRUTH_BOUNDARY,
    }
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out)
    return 0 if manifest["all_gates_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
