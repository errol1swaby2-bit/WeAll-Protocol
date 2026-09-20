from __future__ import annotations

import threading
from pathlib import Path

import pytest

from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="pb001bai-canonical-ledger-checkpoint-atomicity",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _submit_register(ex: WeAllExecutor, signer: str) -> None:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert sub["ok"] is True


def _produce_register_block(ex: WeAllExecutor, signer: str) -> None:
    _submit_register(ex, signer)
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


def _advance_source(source: WeAllExecutor) -> None:
    for signer in ("@u1", "@u2", "@u3"):
        _produce_register_block(source, signer)


class _SyncPeer:
    def __init__(self, source: WeAllExecutor) -> None:
        self.source = source

    def request_state_sync(self, _peer_id, req, **_kwargs):
        return self.source._state_sync_service().handle_request(req)


def _force_snapshot_source(source: WeAllExecutor) -> dict:
    source._db.prune_history(
        retain_last_blocks=1,
        retain_blocks_ms=0,
        retain_bft_candidates_ms=0,
    )
    return build_snapshot_anchor(source.state)


def _sync_snapshot(lagger: WeAllExecutor, source: WeAllExecutor, anchor: dict) -> None:
    lagger.request_and_apply_state_sync(
        _SyncPeer(source),
        "source",
        trusted_anchor=anchor,
        timeout_ms=100,
        sleep_ms=0,
    )


def test_prebuilt_candidate_cannot_commit_after_newer_checkpoint(tmp_path: Path) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)

    _submit_register(lagger, "@local")
    block, new_state, applied_ids, invalid_ids, err = lagger.build_block_candidate(max_txs=1)
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    assert int(block.get("height") or 0) == 1

    anchor = _force_snapshot_source(source)
    _sync_snapshot(lagger, source, anchor)
    assert int(lagger.state.get("height") or 0) == 3

    stale = lagger.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )

    assert stale.ok is False
    assert "stale" in str(stale.error or "")
    assert int(lagger.state.get("height") or 0) == 3
    assert int(lagger._ledger_store.read().get("height") or 0) == 3
    latest = lagger.get_latest_block()
    assert isinstance(latest, dict)
    assert int(latest.get("height") or 0) == 3


def test_produce_block_and_checkpoint_install_are_one_canonical_branch_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    anchor = _force_snapshot_source(source)
    _submit_register(lagger, "@local")

    commit_entered = threading.Event()
    allow_commit = threading.Event()
    produce_done = threading.Event()
    sync_done = threading.Event()
    errors: list[BaseException] = []
    produce_result = []

    original_commit = lagger.commit_block_candidate

    def _blocked_commit(**kwargs):
        commit_entered.set()
        assert allow_commit.wait(timeout=5.0)
        return original_commit(**kwargs)

    monkeypatch.setattr(lagger, "commit_block_candidate", _blocked_commit)

    def _produce() -> None:
        try:
            produce_result.append(lagger.produce_block(max_txs=1))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            produce_done.set()

    def _sync() -> None:
        try:
            _sync_snapshot(lagger, source, anchor)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            sync_done.set()

    producer = threading.Thread(target=_produce, daemon=True)
    producer.start()
    assert commit_entered.wait(timeout=5.0)

    syncer = threading.Thread(target=_sync, daemon=True)
    syncer.start()

    # A canonical block commit that started on the old branch must own the same
    # branch mutation boundary as destructive checkpoint replacement.  The
    # checkpoint may not complete while that block is paused at commit.
    assert sync_done.wait(timeout=0.15) is False

    allow_commit.set()
    assert produce_done.wait(timeout=5.0)
    assert sync_done.wait(timeout=5.0)
    producer.join(timeout=1.0)
    syncer.join(timeout=1.0)

    assert errors == []
    assert len(produce_result) == 1
    assert produce_result[0].ok is True
    assert int(lagger.state.get("height") or 0) == 3
    assert int(lagger._ledger_store.read().get("height") or 0) == 3


def test_apply_block_and_checkpoint_install_are_one_canonical_branch_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    block1 = source.get_block_by_height(1)
    assert isinstance(block1, dict)
    anchor = _force_snapshot_source(source)

    commit_entered = threading.Event()
    allow_commit = threading.Event()
    apply_done = threading.Event()
    sync_done = threading.Event()
    errors: list[BaseException] = []
    apply_result = []

    original_commit = lagger.commit_block_candidate

    def _blocked_commit(**kwargs):
        commit_entered.set()
        assert allow_commit.wait(timeout=5.0)
        return original_commit(**kwargs)

    monkeypatch.setattr(lagger, "commit_block_candidate", _blocked_commit)

    def _apply() -> None:
        try:
            apply_result.append(lagger.apply_block(block1))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            apply_done.set()

    def _sync() -> None:
        try:
            _sync_snapshot(lagger, source, anchor)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            sync_done.set()

    applier = threading.Thread(target=_apply, daemon=True)
    applier.start()
    assert commit_entered.wait(timeout=5.0)

    syncer = threading.Thread(target=_sync, daemon=True)
    syncer.start()

    assert sync_done.wait(timeout=0.15) is False

    allow_commit.set()
    assert apply_done.wait(timeout=5.0)
    assert sync_done.wait(timeout=5.0)
    applier.join(timeout=1.0)
    syncer.join(timeout=1.0)

    assert errors == []
    assert len(apply_result) == 1
    assert apply_result[0].ok is True
    assert int(lagger.state.get("height") or 0) == 3
    assert int(lagger._ledger_store.read().get("height") or 0) == 3
