from __future__ import annotations

import copy
import threading
from pathlib import Path

from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=f"a14-{name}",
        tx_index_path=str(TX_INDEX),
    )


def _empty_candidate(executor: WeAllExecutor, *, ts_ms: int = 1_000):
    block, state, applied_ids, invalid_ids, err = executor.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=ts_ms,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(state, dict)
    return block, state, applied_ids, invalid_ids


def test_a14_f001_stale_persisted_read_cannot_publish_after_real_block_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ex = _executor(tmp_path, "real-commit")
    block, state_after, applied_ids, invalid_ids = _empty_candidate(ex)

    captured = threading.Event()
    release_reader = threading.Event()
    commit_started = threading.Event()
    commit_finished = threading.Event()
    reader_errors: list[BaseException] = []
    commit_errors: list[BaseException] = []
    reader_result: dict = {}
    commit_result: dict = {}

    original_read = ex._ledger_store.read

    def paused_read() -> dict:
        snapshot = original_read()
        assert int(snapshot.get("height") or 0) == 0
        captured.set()
        assert release_reader.wait(timeout=10)
        return snapshot

    monkeypatch.setattr(ex._ledger_store, "read", paused_read)

    def reader() -> None:
        try:
            reader_result.update(ex.read_state())
        except BaseException as exc:  # pragma: no cover - asserted below
            reader_errors.append(exc)

    def commit() -> None:
        try:
            commit_started.set()
            meta = ex.commit_block_candidate(
                block=block,
                new_state=state_after,
                applied_ids=applied_ids,
                invalid_ids=invalid_ids,
            )
            commit_result["ok"] = meta.ok
            commit_result["error"] = meta.error
        except BaseException as exc:  # pragma: no cover - asserted below
            commit_errors.append(exc)
        finally:
            commit_finished.set()

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    assert captured.wait(timeout=10)

    commit_thread = threading.Thread(target=commit, daemon=True)
    commit_thread.start()
    assert commit_started.wait(timeout=10)

    # The reader owns the canonical branch lock across both persisted read and
    # publication. A real block commit therefore cannot cross its durable
    # boundary while the height-N snapshot is paused.
    assert commit_finished.wait(timeout=0.25) is False
    assert int(ex.state.get("height") or 0) == 0

    release_reader.set()
    reader_thread.join(timeout=10)
    commit_thread.join(timeout=10)
    assert not reader_thread.is_alive()
    assert not commit_thread.is_alive()
    assert reader_errors == []
    assert commit_errors == []
    assert commit_result == {"ok": True, "error": ""}
    assert int(reader_result.get("height") or 0) == 0

    # The writer linearizes after the reader and is the final publisher.
    durable = original_read()
    assert int(durable.get("height") or 0) == 1
    assert str(durable.get("tip") or "") == str(block["block_id"])
    assert int(ex.state.get("height") or 0) == 1
    assert str(ex.state.get("tip") or "") == str(block["block_id"])


def test_a14_f001_same_height_tip_and_validator_transition_cannot_be_overwritten(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ex = _executor(tmp_path, "same-height")

    old_snapshot = copy.deepcopy(ex.state)
    old_snapshot["height"] = 7
    old_snapshot["tip"] = "old-tip"
    old_snapshot["tip_hash"] = "old-hash"
    old_snapshot.setdefault("consensus", {})["validator_set"] = {
        "epoch": 3,
        "generation": 3,
        "active": ["@old-a", "@old-b"],
        "set_hash": "old-set",
    }

    new_snapshot = copy.deepcopy(old_snapshot)
    new_snapshot["tip"] = "new-tip"
    new_snapshot["tip_hash"] = "new-hash"
    new_snapshot["consensus"]["validator_set"] = {
        "epoch": 4,
        "generation": 4,
        "active": ["@new-a", "@new-b"],
        "set_hash": "new-set",
    }

    ex.state = copy.deepcopy(old_snapshot)
    durable = {"snapshot": copy.deepcopy(old_snapshot)}

    captured = threading.Event()
    release_reader = threading.Event()
    writer_started = threading.Event()
    writer_finished = threading.Event()
    reader_errors: list[BaseException] = []
    writer_errors: list[BaseException] = []

    def paused_read() -> dict:
        snapshot = copy.deepcopy(durable["snapshot"])
        captured.set()
        assert release_reader.wait(timeout=10)
        return snapshot

    monkeypatch.setattr(ex._ledger_store, "read", paused_read)

    def reader() -> None:
        try:
            ex.read_state()
        except BaseException as exc:  # pragma: no cover - asserted below
            reader_errors.append(exc)

    def canonical_transition() -> None:
        try:
            writer_started.set()
            with ex._bft_branch_guard_lock():
                durable["snapshot"] = copy.deepcopy(new_snapshot)
                ex.state = copy.deepcopy(new_snapshot)
        except BaseException as exc:  # pragma: no cover - asserted below
            writer_errors.append(exc)
        finally:
            writer_finished.set()

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    assert captured.wait(timeout=10)

    writer_thread = threading.Thread(target=canonical_transition, daemon=True)
    writer_thread.start()
    assert writer_started.wait(timeout=10)

    # Height alone cannot distinguish these branches. The shared branch lock
    # orders the complete publication, including tip/hash and validator epoch.
    assert writer_finished.wait(timeout=0.25) is False

    release_reader.set()
    reader_thread.join(timeout=10)
    writer_thread.join(timeout=10)
    assert not reader_thread.is_alive()
    assert not writer_thread.is_alive()
    assert reader_errors == []
    assert writer_errors == []

    assert int(ex.state.get("height") or 0) == 7
    assert ex.state["tip"] == "new-tip"
    assert ex.state["tip_hash"] == "new-hash"
    validator_set = ex.state["consensus"]["validator_set"]
    assert validator_set["epoch"] == 4
    assert validator_set["generation"] == 4
    assert validator_set["set_hash"] == "new-set"
