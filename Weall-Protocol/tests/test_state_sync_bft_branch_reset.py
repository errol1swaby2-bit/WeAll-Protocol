from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.net.state_sync import build_snapshot_anchor
from weall.runtime import bft_artifact_cache as bft_artifact_cache_mod
from weall.runtime.block_hash import compute_block_hash
from weall.runtime.block_id import compute_block_id
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="state-sync-bft-branch-reset",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_register_block(ex: WeAllExecutor, signer: str) -> None:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


def _advance_source(source: WeAllExecutor) -> None:
    for signer in ("@u1", "@u2", "@u3"):
        _produce_register_block(source, signer)


def _stale_proposal_admission_alias(ex: WeAllExecutor) -> dict[str, object]:
    return {
        "chain_id": ex.chain_id,
        "view": 4,
        "block_id": "discarded-proposal",
        "block_hash": "44" * 32,
        "transport_alias": "old-branch-shape",
    }


def _seed_stale_bft_recovery_state(ex: WeAllExecutor) -> tuple[str, str]:
    height = 50
    prev_block_id = "discarded-tip"
    prev_block_hash = "11" * 32
    block_ts_ms = 50_000
    receipts_root = "22" * 32
    header = {
        "chain_id": ex.chain_id,
        "height": height,
        "prev_block_hash": prev_block_hash,
        "block_ts_ms": block_ts_ms,
        "tx_ids": [],
        "receipts_root": receipts_root,
        "state_root": "33" * 32,
    }
    block_hash = compute_block_hash(header=header)
    block_id = compute_block_id(
        chain_id=ex.chain_id,
        height=height,
        prev_block_id=prev_block_id,
        prev_block_hash=prev_block_hash,
        ts_ms=block_ts_ms,
        tx_ids=[],
        receipts_root=receipts_root,
    )
    stale_block = {
        "block_id": block_id,
        "block_hash": block_hash,
        "height": height,
        "prev_block_id": prev_block_id,
        "block_ts_ms": block_ts_ms,
        "header": header,
        "txs": [],
        "receipts": [],
        "validator_epoch": 0,
        "validator_set_hash": "",
    }
    ex._persist_pending_bft_artifact(
        kind="pending_remote_block",
        block_id=block_id,
        payload=stale_block,
    )
    ex._restore_pending_bft_frontier()

    stale_timeout = {
        "t": "TIMEOUT",
        "chain_id": ex.chain_id,
        "view": 4,
        "high_qc_id": "discarded-tip",
        "signer": "@lagger",
        "pubkey": "stale-pubkey",
        "sig": "stale-signature",
        "validator_epoch": 0,
        "validator_set_hash": "",
    }
    ex._bft_outbox_store.enqueue(
        key="timeout:4:@lagger:discarded-tip",
        kind="timeout",
        payload=stale_timeout,
    )

    # Also seed purely in-memory branch identity/resource caches. A destructive
    # checkpoint must not retain these even when validator epoch/set is unchanged.
    ex._known_block_hashes[block_id] = block_hash
    ex._known_block_ids_by_hash[block_hash] = block_id
    ex._conflicted_block_ids[block_id] = {"reason": "old-branch"}
    ex._conflicted_block_hashes[block_hash] = {"reason": "old-branch"}
    ex._recent_bft_timeouts["stale-timeout"] = 1
    bft_artifact_cache_mod._record_bft_admission_alias(
        ex,
        "proposal",
        _stale_proposal_admission_alias(ex),
    )
    return block_id, block_hash


def _aux_counts(ex: WeAllExecutor) -> tuple[int, int]:
    with ex._aux_db.connection() as con:
        pending = con.execute("SELECT COUNT(*) AS n FROM bft_pending_artifacts;").fetchone()
        outbox = con.execute("SELECT COUNT(*) AS n FROM bft_outbox;").fetchone()
    return int(pending["n"]), int(outbox["n"])


class _SyncPeer:
    def __init__(self, source: WeAllExecutor) -> None:
        self.source = source

    def request_state_sync(self, _peer_id, req, **_kwargs):
        return self.source._state_sync_service().handle_request(req)


def test_checkpoint_sync_purges_old_branch_bft_recovery_state(tmp_path: Path) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    stale_block_id, stale_block_hash = _seed_stale_bft_recovery_state(lagger)

    assert list(lagger._pending_remote_blocks) == [stale_block_id]
    assert len(lagger.bft_pending_outbound_messages()) == 1
    assert (
        lagger.bft_artifact_was_accepted("proposal", _stale_proposal_admission_alias(lagger))
        is True
    )
    assert _aux_counts(lagger) == (1, 1)

    source._db.prune_history(
        retain_last_blocks=1,
        retain_blocks_ms=0,
        retain_bft_candidates_ms=0,
    )
    anchor = build_snapshot_anchor(source.state)
    lagger.request_and_apply_state_sync(
        _SyncPeer(source),
        "source",
        trusted_anchor=anchor,
        timeout_ms=100,
        sleep_ms=0,
    )

    assert int(lagger.state.get("height") or 0) == int(source.state.get("height") or 0)
    assert list(lagger._pending_remote_blocks) == []
    assert lagger.bft_pending_outbound_messages() == []
    assert lagger._known_block_hashes.get(stale_block_id) is None
    assert lagger._known_block_ids_by_hash.get(stale_block_hash) is None
    assert lagger._conflicted_block_ids.get(stale_block_id) is None
    assert lagger._conflicted_block_hashes.get(stale_block_hash) is None
    assert lagger._recent_bft_timeouts.get("stale-timeout") is None
    assert lagger._recent_bft_admission_aliases == {}
    assert (
        lagger.bft_artifact_was_accepted("proposal", _stale_proposal_admission_alias(lagger))
        is False
    )
    assert _aux_counts(lagger) == (0, 0)

    restarted = _make_executor(tmp_path, "lagger")
    assert restarted.bft_pending_outbound_messages() == []
    assert list(restarted._pending_remote_blocks) == []
    assert _aux_counts(restarted) == (0, 0)


def test_restart_reconciles_crash_after_ledger_checkpoint_before_aux_reset(
    tmp_path: Path,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    _seed_stale_bft_recovery_state(lagger)

    # Old branch restart hint must also be separated from the checkpoint branch.
    lagger._bft_journal.append(
        "bft_view_advanced",
        chain_id=lagger.chain_id,
        node_id=lagger.node_id,
        view=99,
    )
    lagger._bft_journal.append(
        "bft_timeout_emitted",
        chain_id=lagger.chain_id,
        node_id=lagger.node_id,
        view=98,
        high_qc_id="discarded-tip",
        timeout_ms=1000,
    )

    # Simulate the exact cross-DB crash window: the canonical ledger checkpoint
    # commits, but the process dies before executor-side auxiliary cleanup runs.
    snapshot = copy.deepcopy(source.state)
    snapshot.pop("bft", None)
    checkpoint = source.get_latest_block()
    assert isinstance(checkpoint, dict)
    lagger._ledger_store.install_state_sync_checkpoint(
        state=snapshot,
        checkpoint_block=checkpoint,
    )
    assert _aux_counts(lagger) == (1, 1)

    restarted = _make_executor(tmp_path, "lagger")

    assert int(restarted.state.get("height") or 0) == int(source.state.get("height") or 0)
    assert restarted.bft_pending_outbound_messages() == []
    assert list(restarted._pending_remote_blocks) == []
    assert _aux_counts(restarted) == (0, 0)
    assert int(restarted._bft.view) != 99

    with restarted._aux_db.connection() as con:
        marker = con.execute(
            "SELECT value FROM meta WHERE key='state_sync_bft_reset_checkpoint_hash' LIMIT 1;"
        ).fetchone()
    assert marker is not None
    assert str(marker["value"] or "") == restarted._ledger_checkpoint_block_hash()

    restart_hints = restarted._bft_journal.bootstrap_state(strict=True)
    assert int(restart_hints.get("last_view") or 0) != 99
    assert int(restart_hints.get("last_timeout_view") or -1) == -1
    assert str(restart_hints.get("last_high_qc_id") or "") == ""
    assert list(restart_hints.get("pending_outbound") or []) == []


def test_checkpoint_install_failure_still_clears_old_branch_bft_replay_state(
    tmp_path: Path, monkeypatch
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    _seed_stale_bft_recovery_state(lagger)

    source._db.prune_history(
        retain_last_blocks=1,
        retain_blocks_ms=0,
        retain_bft_candidates_ms=0,
    )
    anchor = build_snapshot_anchor(source.state)
    before_height = int(lagger.state.get("height") or 0)

    def _fail_install(*, state, checkpoint_block):
        del state, checkpoint_block
        raise RuntimeError("injected-checkpoint-write-failure")

    monkeypatch.setattr(lagger._ledger_store, "install_state_sync_checkpoint", _fail_install)

    with pytest.raises(
        ExecutorError,
        match="state_sync_checkpoint_install_failed:injected-checkpoint-write-failure",
    ):
        lagger.request_and_apply_state_sync(
            _SyncPeer(source),
            "source",
            trusted_anchor=anchor,
            timeout_ms=100,
            sleep_ms=0,
        )

    # Canonical replacement did not occur, but old branch-local replay state was
    # deliberately discarded before the cross-DB commit attempt. That is the
    # fail-closed side of the ordering tradeoff.
    assert int(lagger.state.get("height") or 0) == before_height
    assert lagger.bft_pending_outbound_messages() == []
    assert list(lagger._pending_remote_blocks) == []
    assert lagger._recent_bft_admission_aliases == {}
    assert (
        lagger.bft_artifact_was_accepted("proposal", _stale_proposal_admission_alias(lagger))
        is False
    )
    assert _aux_counts(lagger) == (0, 0)


def test_checkpoint_post_commit_housekeeping_failure_is_not_reported_as_noncommit(
    tmp_path: Path, monkeypatch
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)

    source._db.prune_history(
        retain_last_blocks=1,
        retain_blocks_ms=0,
        retain_bft_candidates_ms=0,
    )
    anchor = build_snapshot_anchor(source.state)

    def _fail_persist_bft_state() -> None:
        raise RuntimeError("injected-post-checkpoint-persist-failure")

    monkeypatch.setattr(lagger, "_persist_bft_state", _fail_persist_bft_state)

    with pytest.raises(
        ExecutorError,
        match=(
            "state_sync_checkpoint_committed_restart_required:"
            "state_sync_checkpoint_post_commit_failed:RuntimeError:"
            "injected-post-checkpoint-persist-failure"
        ),
    ):
        lagger.request_and_apply_state_sync(
            _SyncPeer(source),
            "source",
            trusted_anchor=anchor,
            timeout_ms=100,
            sleep_ms=0,
        )

    expected_height = int(source.state.get("height") or 0)
    expected_tip = str(source.state.get("tip") or "")
    assert int(lagger.state.get("height") or 0) == expected_height
    assert str(lagger.state.get("tip") or "") == expected_tip

    with lagger._db.connection() as con:
        row = con.execute(
            "SELECT height, block_id FROM ledger_state WHERE id=1 LIMIT 1;"
        ).fetchone()
    assert row is not None
    assert int(row["height"]) == expected_height
    assert str(row["block_id"] or "") == expected_tip

    post_commit_error = str(getattr(lagger, "_post_commit_housekeeping_error", "") or "")
    assert post_commit_error.startswith("state_sync_checkpoint_post_commit_failed:")
    assert lagger._validator_signing_enabled is False
    assert lagger._observer_mode_forced is True
    assert lagger.block_loop_unhealthy is True

    meta = lagger.produce_block(max_txs=0, allow_empty=True)
    assert meta.ok is False
    assert meta.error == f"executor_unhealthy:{post_commit_error}"

    with pytest.raises(ExecutorError, match=f"executor_unhealthy:{post_commit_error}"):
        lagger.request_and_apply_state_sync(
            _SyncPeer(source),
            "source",
            trusted_anchor=anchor,
            timeout_ms=100,
            sleep_ms=0,
        )

    restarted = _make_executor(tmp_path, "lagger")
    assert int(restarted.state.get("height") or 0) == expected_height
    assert str(restarted.state.get("tip") or "") == expected_tip
    assert str(getattr(restarted, "_post_commit_housekeeping_error", "") or "") == ""
