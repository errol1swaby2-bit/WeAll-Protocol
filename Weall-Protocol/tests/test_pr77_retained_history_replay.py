from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from scripts.pr77_retained_history_replay import (
    ReplayEvidenceError,
    file_sha256,
    inspect_offline_source,
    replay_offline_source,
    validate_report_destination,
    write_report_exclusively,
)


def _fixture_db(
    tmp_path: Path, *, heights: tuple[int, ...] = (1, 2), chain_id: str = "test-chain"
) -> Path:
    db_path = tmp_path / "offline-copy.sqlite"
    with sqlite3.connect(db_path) as con:
        con.execute("CREATE TABLE blocks(height INTEGER PRIMARY KEY, block_json TEXT NOT NULL)")
        con.execute(
            "CREATE TABLE ledger_state(id INTEGER PRIMARY KEY, height INTEGER, state_json TEXT)"
        )
        for height in heights:
            block = {
                "height": height,
                "block_id": f"block-{height}",
                "header": {
                    "state_root": "b" * 64,
                    "receipts_root": "c" * 64,
                },
            }
            con.execute(
                "INSERT INTO blocks(height, block_json) VALUES(?, ?)",
                (height, json.dumps(block)),
            )
        state = {"chain_id": chain_id, "height": max(heights), "accounts": {}}
        con.execute(
            "INSERT INTO ledger_state(id, height, state_json) VALUES(1, ?, ?)",
            (max(heights), json.dumps(state)),
        )
    return db_path


def test_readonly_preflight_accepts_contiguous_archive_without_changing_bytes(
    tmp_path: Path,
) -> None:
    source = _fixture_db(tmp_path)
    before = source.read_bytes()
    state, blocks = inspect_offline_source(source, file_sha256(source), "test-chain")
    assert state["height"] == 2
    assert [block["height"] for block in blocks] == [1, 2]
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    ("heights", "expected"),
    (
        ((1, 3), "offline_source_height_gap:2"),
        ((2,), "offline_source_height_gap:1"),
    ),
)
def test_preflight_rejects_gapped_block_histories(
    tmp_path: Path, heights: tuple[int, ...], expected: str
) -> None:
    source = _fixture_db(tmp_path, heights=heights)
    with pytest.raises(ReplayEvidenceError, match=expected):
        inspect_offline_source(source, file_sha256(source), "test-chain")


def test_preflight_rejects_wrong_chain_and_digest(tmp_path: Path) -> None:
    source = _fixture_db(tmp_path)
    with pytest.raises(ReplayEvidenceError, match="chain_identity_mismatch"):
        inspect_offline_source(source, file_sha256(source), "other-chain")
    with pytest.raises(ReplayEvidenceError, match="source_sha256_mismatch"):
        inspect_offline_source(source, "0" * 64, "test-chain")


def test_preflight_rejects_live_wal_sidecar_and_symlink(tmp_path: Path) -> None:
    source = _fixture_db(tmp_path)
    Path(f"{source}-wal").write_bytes(b"unsafe-live-copy")
    with pytest.raises(ReplayEvidenceError, match="wal_or_shm"):
        inspect_offline_source(source, file_sha256(source), "test-chain")
    Path(f"{source}-wal").unlink()
    alias = tmp_path / "alias.sqlite"
    alias.symlink_to(source)
    with pytest.raises(ReplayEvidenceError, match="symlink"):
        inspect_offline_source(alias, file_sha256(source), "test-chain")


def test_checkout_mismatch_fails_before_opening_archive_or_creating_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _fixture_db(tmp_path)
    monkeypatch.setattr(
        "scripts.pr77_retained_history_replay.subprocess.check_output",
        lambda *args, **kwargs: "f" * 40 + "\n",
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with pytest.raises(ReplayEvidenceError, match="checkout_commit_mismatch"):
        replay_offline_source(
            source=source,
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            chain_id="test-chain",
            scratch_dir=scratch,
            tx_index=tmp_path / "index.json",
            tx_index_sha256="1" * 64,
            expected_commit="e" * 40,
        )
    assert not list(scratch.iterdir())


def test_synthetic_stored_blocks_replay_through_real_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute the full archive/replay path on a synthetic 3-block chain only.

    This test cannot certify any retained historical ledger or two-node BFT.
    """
    import subprocess

    from weall.runtime.replay_consistency import build_sample_chain

    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    sample = build_sample_chain(
        work_dir=str(tmp_path / "synthetic"), chain_id_prefix="pr77-archive-fixture"
    )
    assert sample["ok"] is True
    assert sample["source_manifest"]["height"] == 3

    source = Path(sample["source_db"])
    scratch = tmp_path / "independent-scratch"
    scratch.mkdir()
    repo_root = Path(__file__).resolve().parents[2]
    tx_index = repo_root / "Weall-Protocol" / "generated" / "tx_index.json"
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True).strip()
    report = replay_offline_source(
        source=source,
        source_sha256=file_sha256(source),
        chain_id=sample["chain_id"],
        scratch_dir=scratch,
        tx_index=tx_index,
        tx_index_sha256=file_sha256(tx_index),
        expected_commit=commit,
    )
    assert report["ok"] is True
    assert report["block_count"] == 3
    assert report["final_state_root"] == sample["source_manifest"]["computed_state_root"]
    commitments = report["per_height_commitments"]
    assert [record["height"] for record in commitments] == [1, 2, 3]
    assert all(
        record["block_hash"] and record["state_root"] and record["receipts_root"]
        for record in commitments
    )
    assert commitments[-1]["state_root"] == report["final_state_root"]
    assert report["historical_provenance_verified"] is False
    assert report["old_version_compatibility_proven"] is False
    assert report["independent_two_node_consensus_proven"] is False


def test_report_destination_never_overwrites_source_or_pinned_tx_index(
    tmp_path: Path,
) -> None:
    source = _fixture_db(tmp_path)
    tx_index = tmp_path / "tx-index.json"
    tx_index.write_text("{}", encoding="utf-8")
    source_bytes = source.read_bytes()
    index_bytes = tx_index.read_bytes()

    for destination in (source, tx_index):
        with pytest.raises(ReplayEvidenceError, match="report_overlaps_protected_evidence"):
            validate_report_destination(destination, source=source, tx_index=tx_index)
    assert source.read_bytes() == source_bytes
    assert tx_index.read_bytes() == index_bytes


def test_report_destination_rejects_preexisting_or_symlink_files(
    tmp_path: Path,
) -> None:
    source = _fixture_db(tmp_path)
    tx_index = tmp_path / "tx-index.json"
    tx_index.write_text("{}", encoding="utf-8")
    report = tmp_path / "report.json"
    validate_report_destination(report, source=source, tx_index=tx_index)
    write_report_exclusively(report, '{"ok":false}\n')
    assert report.read_text(encoding="utf-8") == '{"ok":false}\n'
    with pytest.raises(ReplayEvidenceError, match="report_destination_already_exists"):
        write_report_exclusively(report, "must-not-overwrite")
    assert report.read_text(encoding="utf-8") == '{"ok":false}\n'

    symlink = tmp_path / "report-alias.json"
    symlink.symlink_to(report)
    with pytest.raises(ReplayEvidenceError, match="report_destination_already_exists"):
        validate_report_destination(symlink, source=source, tx_index=tx_index)


@pytest.mark.parametrize("scratch_state", ("nonempty", "symlink"))
def test_replay_rejects_unclean_or_symlinked_scratch_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scratch_state: str
) -> None:
    source = _fixture_db(tmp_path)
    tx_index = tmp_path / "tx-index.json"
    tx_index.write_text("{}", encoding="utf-8")
    scratch = tmp_path / "scratch"
    if scratch_state == "nonempty":
        scratch.mkdir()
        (scratch / "existing-evidence.json").write_text("preserve", encoding="utf-8")
        expected = "scratch_directory_must_be_empty"
    else:
        empty = tmp_path / "real-empty"
        empty.mkdir()
        scratch.symlink_to(empty, target_is_directory=True)
        expected = "scratch_directory_missing_or_symlink"
    monkeypatch.setattr(
        "scripts.pr77_retained_history_replay.subprocess.check_output",
        lambda *args, **kwargs: "f" * 40 + "\n",
    )
    with pytest.raises(ReplayEvidenceError, match=expected):
        replay_offline_source(
            source=source,
            source_sha256=file_sha256(source),
            chain_id="test-chain",
            scratch_dir=scratch,
            tx_index=tx_index,
            tx_index_sha256=file_sha256(tx_index),
            expected_commit="f" * 40,
        )
    assert not (tmp_path / "pr77_retained_replay.sqlite").exists()
    if scratch_state == "nonempty":
        assert (scratch / "existing-evidence.json").read_text(encoding="utf-8") == "preserve"
