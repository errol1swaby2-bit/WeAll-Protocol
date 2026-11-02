#!/usr/bin/env python3
"""Read-only replay of a preserved, OFFLINE WeAll SQLite ledger copy.

Success proves one code revision re-applies stored blocks to a fresh executor.
It does NOT prove the ledger is historical, old-version compatibility, or
independent two-node consensus. Never supply a live node database here.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path
from typing import Any

from weall.runtime.block_commitment_validation import (
    BlockCommitmentBindingError,
    ensure_complete_block_commitments,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from tooling.severe_case_signed_opening_review import review_signed_dispute_opening

Json = dict[str, Any]
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")


class ReplayEvidenceError(RuntimeError):
    """Fail-closed input, provenance, or replay mismatch."""


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_offline_source(
    source: Path, expected_sha256: str, chain_id: str
) -> tuple[Json, list[Json]]:
    """Read preserved blocks without ever opening source SQLite for writing."""
    if not _SHA256.fullmatch(expected_sha256):
        raise ReplayEvidenceError("invalid_source_sha256")
    if not source.is_file() or source.is_symlink():
        raise ReplayEvidenceError("offline_source_missing_or_symlink")
    if any(Path(f"{source}{suffix}").exists() for suffix in ("-wal", "-shm")):
        raise ReplayEvidenceError("offline_source_has_wal_or_shm_sidecar")
    if file_sha256(source) != expected_sha256:
        raise ReplayEvidenceError("offline_source_sha256_mismatch")
    try:
        with closing(sqlite3.connect(f"{source.as_uri()}?mode=ro&immutable=1", uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
                raise ReplayEvidenceError("offline_source_sqlite_integrity_failure")
            tables = {
                row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not {"blocks", "ledger_state"}.issubset(tables):
                raise ReplayEvidenceError("offline_source_missing_chain_tables")
            row = db.execute("SELECT height, state_json FROM ledger_state WHERE id=1").fetchone()
            if row is None:
                raise ReplayEvidenceError("offline_source_missing_ledger_state")
            state = json.loads(str(row["state_json"]))
            if not isinstance(state, dict) or str(state.get("chain_id") or "") != chain_id:
                raise ReplayEvidenceError("offline_source_chain_identity_mismatch")
            snapshot_height = int(row["height"])
            blocks: list[Json] = []
            for expected_height, entry in enumerate(
                db.execute("SELECT height, block_json FROM blocks ORDER BY height"),
                start=1,
            ):
                height = int(entry["height"])
                if height != expected_height:
                    raise ReplayEvidenceError(f"offline_source_height_gap:{expected_height}")
                block = json.loads(str(entry["block_json"]))
                if not isinstance(block, dict) or int(block.get("height") or 0) != height:
                    raise ReplayEvidenceError(f"offline_source_block_height_mismatch:{height}")
                header = block.get("header")
                if not isinstance(header, dict) or not all(
                    str(value or "")
                    for value in (
                        block.get("block_id"),
                        header.get("state_root"),
                        header.get("receipts_root"),
                    )
                ):
                    raise ReplayEvidenceError(f"offline_source_missing_commitment:{height}")
                # The block hash may be derived from its signed/committed header;
                # it need not be stored as a top-level JSON key.
                blocks.append(block)
    except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ReplayEvidenceError(f"offline_source_invalid:{type(exc).__name__}") from exc
    if not blocks or int(state.get("height") or 0) != len(blocks) or snapshot_height != len(blocks):
        raise ReplayEvidenceError("offline_source_snapshot_height_mismatch")
    if file_sha256(source) != expected_sha256:
        raise ReplayEvidenceError("offline_source_changed_during_read")
    return state, blocks


def replay_offline_source(
    *,
    source: Path,
    source_sha256: str,
    chain_id: str,
    scratch_dir: Path,
    tx_index: Path,
    tx_index_sha256: str,
    expected_commit: str,
    opening_tx_id: str | None = None,
    opening_case_id: str | None = None,
) -> Json:
    """Compare blocks and optionally observe one signed opening during replay.

    The optional witness is derived only from re-executed predecessor/resulting
    states; it does not establish the supplied archive's external provenance.
    """
    if (opening_tx_id is None) != (opening_case_id is None):
        raise ReplayEvidenceError("opening_witness_requires_tx_id_and_case_id")
    if opening_tx_id is not None:
        if not isinstance(opening_tx_id, str) or not re.fullmatch(
            r"tx:[0-9a-f]{64}", opening_tx_id
        ):
            raise ReplayEvidenceError("opening_witness_tx_id_invalid")
        if not isinstance(opening_case_id, str) or not opening_case_id.strip():
            raise ReplayEvidenceError("opening_witness_case_id_invalid")
    if not _GIT_SHA.fullmatch(expected_commit):
        raise ReplayEvidenceError("invalid_expected_commit")
    if not _SHA256.fullmatch(tx_index_sha256):
        raise ReplayEvidenceError("invalid_tx_index_sha256")
    actual_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if actual_commit != expected_commit:
        raise ReplayEvidenceError("checkout_commit_mismatch")
    if not tx_index.is_file() or file_sha256(tx_index) != tx_index_sha256:
        raise ReplayEvidenceError("tx_index_sha256_mismatch")
    source_state, blocks = inspect_offline_source(source, source_sha256, chain_id)
    if not scratch_dir.is_dir() or scratch_dir.is_symlink():
        raise ReplayEvidenceError("scratch_directory_missing_or_symlink")
    if any(scratch_dir.iterdir()):
        raise ReplayEvidenceError("scratch_directory_must_be_empty")
    target = scratch_dir.resolve() / "pr77_retained_replay.sqlite"
    if target.exists() or source.resolve() == target:
        raise ReplayEvidenceError("scratch_destination_exists_or_overlaps_source")
    # The executor has write access to scratch only; the source remains immutable.
    executor = WeAllExecutor(
        db_path=str(target),
        node_id="pr77-offline-retained-replay",
        chain_id=chain_id,
        tx_index_path=str(tx_index.resolve()),
    )
    if int(executor.read_state().get("height") or 0) != 0:
        raise ReplayEvidenceError("scratch_executor_not_at_genesis")
    per_height_commitments: list[Json] = []
    opening_witness: Json | None = None
    for height, block in enumerate(blocks, start=1):
        tx_ids = block.get("header", {}).get("tx_ids")
        matches = (
            tx_ids.count(opening_tx_id)
            if opening_tx_id is not None and isinstance(tx_ids, list)
            else 0
        )
        if matches > 1 or (matches and opening_witness is not None):
            raise ReplayEvidenceError("opening_witness_duplicate_tx_id")
        if matches and height == 1:
            raise ReplayEvidenceError("opening_witness_no_replayed_predecessor")
        pre_state = copy.deepcopy(dict(executor.read_state())) if matches else None
        pre_root = compute_state_root(pre_state) if pre_state is not None else ""
        if matches and pre_root != per_height_commitments[-1]["state_root"]:
            raise ReplayEvidenceError("opening_witness_predecessor_root_mismatch")
        meta = executor.apply_block(copy.deepcopy(block))
        if not bool(meta.ok):
            raise ReplayEvidenceError(f"historical_apply_rejected:{height}:{str(meta.error)[:120]}")
        observed = executor.get_block_by_height(height)
        if not isinstance(observed, dict):
            raise ReplayEvidenceError(f"historical_block_not_persisted:{height}")
        try:
            original, _ = ensure_complete_block_commitments(block=block, chain_id=chain_id)
            current, _ = ensure_complete_block_commitments(block=observed, chain_id=chain_id)
        except BlockCommitmentBindingError as exc:
            raise ReplayEvidenceError(f"historical_block_binding_invalid:{height}:{exc}") from exc
        if original != current:
            raise ReplayEvidenceError(f"historical_block_commitment_mismatch:{height}")
        root = compute_state_root(dict(executor.read_state()))
        if root != str(block["header"]["state_root"]):
            raise ReplayEvidenceError(f"historical_state_root_mismatch:{height}")
        header = block["header"]
        per_height_commitments.append(
            {
                "height": height,
                "block_id": str(original["block_id"]),
                "block_hash": str(original["block_hash"]),
                "state_root": root,
                "receipts_root": str(header["receipts_root"]),
            }
        )
        if matches:
            post_state = dict(executor.read_state())
            cases = post_state.get("disputes_by_id")
            case = cases.get(opening_case_id) if isinstance(cases, dict) else None
            if not isinstance(case, dict):
                raise ReplayEvidenceError("opening_witness_case_not_in_replayed_state")
            review = review_signed_dispute_opening(
                case=case,
                block=current,
                pre_state=pre_state,
                chain_id=chain_id,
                opening_tx_id=opening_tx_id,
            )
            missing = [
                key for key, observed in review["observations"].items() if observed is not True
            ]
            if missing:
                raise ReplayEvidenceError(
                    "opening_witness_not_source_bound:" + ",".join(sorted(missing))
                )
            opening_witness = {
                "schema": "weall.pr77.replayed_signed_opening_observation.v0",
                "height": height,
                "opening_tx_id": opening_tx_id,
                "case_id": opening_case_id,
                "block_id": str(original["block_id"]),
                "block_hash": str(original["block_hash"]),
                "pre_state_root": pre_root,
                "post_state_root": root,
                "observations": dict(review["observations"]),
                "constitutional_authorization": "NOT_ESTABLISHED",
                "may_classify_canonical_case": False,
                "may_enqueue_account_ban": False,
            }
    if opening_tx_id is not None and opening_witness is None:
        raise ReplayEvidenceError("opening_witness_tx_id_not_found")
    final_root = compute_state_root(dict(executor.read_state()))
    if final_root != compute_state_root(source_state):
        raise ReplayEvidenceError("retained_head_state_root_mismatch")
    if file_sha256(source) != source_sha256:
        raise ReplayEvidenceError("offline_source_changed_during_replay")
    return {
        "ok": True,
        "schema": "weall.pr77.retained_replay.v1",
        "chain_id": chain_id,
        "execution_commit": actual_commit,
        "source_db_sha256": source_sha256,
        "tx_index_sha256": tx_index_sha256,
        "block_count": len(blocks),
        "final_state_root": final_root,
        "per_height_commitments": per_height_commitments,
        "proof_scope": "single_revision_replay_against_recorded_commitments",
        **({"signed_opening_witness": opening_witness} if opening_witness else {}),
        "historical_provenance_verified": False,
        "old_version_compatibility_proven": False,
        "independent_two_node_consensus_proven": False,
    }


def validate_report_destination(report: Path, *, source: Path, tx_index: Path) -> None:
    """Refuse overwriting input evidence or any existing report.

    Report creation must use exclusive-create mode after this check as well.
    """
    if report.resolve() in {source.resolve(), tx_index.resolve()}:
        raise ReplayEvidenceError("report_overlaps_protected_evidence")
    if report.exists() or report.is_symlink():
        raise ReplayEvidenceError("report_destination_already_exists")
    if not report.parent.is_dir() or report.parent.is_symlink():
        raise ReplayEvidenceError("report_parent_missing_or_symlink")


def write_report_exclusively(report: Path, rendered: str) -> None:
    """An existing file or symlink must never be truncated by evidence output."""
    try:
        with report.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    except FileExistsError as exc:
        raise ReplayEvidenceError("report_destination_already_exists") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-source-db", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--tx-index", type=Path, required=True)
    parser.add_argument("--tx-index-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--opening-tx-id", default=None)
    parser.add_argument("--opening-case-id", default=None)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    safe_report = False
    try:
        if args.report:
            validate_report_destination(
                args.report, source=args.offline_source_db, tx_index=args.tx_index
            )
            safe_report = True
        result = replay_offline_source(
            source=args.offline_source_db.absolute(),
            source_sha256=args.source_sha256,
            chain_id=args.chain_id,
            scratch_dir=args.scratch_dir,
            tx_index=args.tx_index,
            tx_index_sha256=args.tx_index_sha256,
            expected_commit=args.expected_commit,
            opening_tx_id=args.opening_tx_id,
            opening_case_id=args.opening_case_id,
        )
    except (ReplayEvidenceError, OSError, subprocess.CalledProcessError) as exc:
        result = {
            "ok": False,
            "schema": "weall.pr77.retained_replay.v1",
            "failure": str(exc),
            "historical_provenance_verified": False,
            "old_version_compatibility_proven": False,
            "independent_two_node_consensus_proven": False,
        }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.report and safe_report:
        try:
            write_report_exclusively(args.report, rendered)
        except (ReplayEvidenceError, OSError) as exc:
            print(json.dumps({"ok": False, "failure": str(exc)}, sort_keys=True))
            return 1
    print(rendered, end="")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
