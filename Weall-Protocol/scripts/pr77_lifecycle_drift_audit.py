#!/usr/bin/env python3
"""Diagnose PR77 lifecycle drift without accepting any new semantic evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
KNOWN_ROLE_VECTORS = frozenset({
    "ROLE_JUROR_ACTIVATE",
    "ROLE_JUROR_REINSTATE",
    "ROLE_JUROR_SUSPEND",
    "ROLE_NODE_OPERATOR_SUSPEND",
})


def leaf_diffs(old: Any, new: Any, path: str = "") -> list[dict[str, Any]]:
    """List path-level JSON differences, including missing keys."""
    if isinstance(old, dict) and isinstance(new, dict):
        found: list[dict[str, Any]] = []
        for key in sorted(set(old) | set(new)):
            segment = str(key).replace("~", "~0").replace("/", "~1")
            child = f"{path}/{segment}"
            if key not in old or key not in new:
                found.append({
                    "path": child,
                    "old": old.get(key, "<missing>"),
                    "new": new.get(key, "<missing>"),
                })
            else:
                found.extend(leaf_diffs(old[key], new[key], child))
        return found
    if isinstance(old, list) and isinstance(new, list):
        found = []
        for index in range(max(len(old), len(new))):
            child = f"{path}/{index}"
            if index >= len(old) or index >= len(new):
                found.append({
                    "path": child,
                    "old": old[index] if index < len(old) else "<missing>",
                    "new": new[index] if index < len(new) else "<missing>",
                })
            else:
                found.extend(leaf_diffs(old[index], new[index], child))
        return found
    if old == new and type(old) is type(new):
        return []
    return [{"path": path or "/", "old": old, "new": new}]


def build_diagnostic() -> tuple[dict[str, Any], dict[str, Any]]:
    """Regenerate 236 vectors in memory, compare four changed rows with deepcopy."""
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import gen_tx_lifecycle_assurance_v1_5 as generator
    from weall.runtime.domain_apply import (
        apply_tx_atomic_meta_bounded_rollback,
        apply_tx_atomic_meta_deepcopy,
    )
    from weall.runtime.state_hash import compute_state_root

    tracked_bytes = generator.OUTPUT_PATH.read_bytes()
    original = json.loads(tracked_bytes)
    candidate = generator.build_manifest()
    prior_rows = original.get("rows")
    next_rows = candidate.get("rows")
    if not isinstance(prior_rows, list) or not isinstance(next_rows, list):
        raise RuntimeError("lifecycle_missing_rows")
    if len(prior_rows) != 236 or len(next_rows) != 236:
        raise RuntimeError("lifecycle_inventory_not_236")
    prior = {row["tx_type"]: row for row in prior_rows}
    current = {row["tx_type"]: row for row in next_rows}
    if len(prior) != 236 or len(current) != 236 or prior.keys() != current.keys():
        raise RuntimeError("lifecycle_inventory_changed_or_duplicate")

    changed = sorted(key for key in prior if prior[key] != current[key])
    fixture = generator.load_fixture_module()
    semantic_rows = {
        row["tx_type"]: row for row in generator.load_semantic_manifest()["rows"]
    }
    investigations: dict[str, Any] = {}
    for tx_type in changed:
        before = fixture._base_state()
        envelope = fixture._prepared_envelope(before, semantic_rows[tx_type])
        oracle = copy.deepcopy(before)
        bounded = copy.deepcopy(before)
        old_state_root = compute_state_root(before)
        oracle_meta = apply_tx_atomic_meta_deepcopy(oracle, copy.deepcopy(envelope))
        bounded_meta = apply_tx_atomic_meta_bounded_rollback(
            bounded, copy.deepcopy(envelope)
        )
        new_state_root = compute_state_root(bounded)
        execution = current[tx_type]["successful_execution"]
        if (
            old_state_root != execution["state_root_before"]
            or new_state_root != execution["state_root_after"]
            or bounded_meta != execution["apply_expected"]["metadata"]
        ):
            raise RuntimeError(f"candidate_internally_inconsistent:{tx_type}")
        diffs = leaf_diffs(prior[tx_type], current[tx_type])
        investigations[tx_type] = {
            "tracked_to_candidate": diffs,
            "changed_pointers": [entry["path"] for entry in diffs],
            "current_state_transition_paths": [
                entry["path"] for entry in leaf_diffs(before, bounded)
            ],
            "current_fixture_before_root": old_state_root,
            "current_fixture_after_root": new_state_root,
            "deepcopy_metadata_equal": oracle_meta == bounded_meta,
            "deepcopy_state_equal": oracle == bounded,
            "deepcopy_root_equal": compute_state_root(oracle) == new_state_root,
            "historical_pre_fix_state_available": False,
        }

    candidate_bytes = (
        json.dumps(candidate, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    report = {
        "schema": "weall.pr77.lifecycle_adjudication_diagnostic.v1",
        "provenance": "current_synthetic_fixture_only",
        "authoritative_historical_chain_provided": False,
        "independent_review_or_semantic_approval": False,
        "must_not_refresh_tracked_manifest_automatically": True,
        "tracked_manifest_sha256": hashlib.sha256(tracked_bytes).hexdigest(),
        "candidate_manifest_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
        "changed_tx_types": changed,
        "changed_outside_four_known_role_vectors": sorted(
            set(changed) - KNOWN_ROLE_VECTORS
        ),
        "changed_top_level_fields": sorted(
            key for key in set(original) | set(candidate)
            if key != "rows" and original.get(key) != candidate.get(key)
        ),
        "investigations": investigations,
        "all_changed_rows_match_deepcopy_oracle": all(
            row["deepcopy_metadata_equal"]
            and row["deepcopy_state_equal"]
            and row["deepcopy_root_equal"]
            for row in investigations.values()
        ),
    }
    return report, candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    protected = ROOT / "generated" / "tx_lifecycle_assurance_v1_5.json"
    destinations = (args.report, args.candidate)
    if (
        any(path.exists() or path.is_symlink() for path in destinations)
        or destinations[0].resolve() == destinations[1].resolve()
        or protected.resolve() in {path.resolve() for path in destinations}
    ):
        raise SystemExit("refuse_to_overwrite_diagnostic_or_tracked_manifest")
    report, candidate = build_diagnostic()
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.candidate.write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "changed_tx_types": report["changed_tx_types"],
        "changed_pointers": {
            name: row["changed_pointers"]
            for name, row in report["investigations"].items()
        },
        "oracle_parity": report["all_changed_rows_match_deepcopy_oracle"],
        "historical_compatibility_proven": False,
    }, indent=2, sort_keys=True))
    if report["changed_tx_types"]:
        print("FAIL_CLOSED: review drift; do not automatically refresh evidence")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
