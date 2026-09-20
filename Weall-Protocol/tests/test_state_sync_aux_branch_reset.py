from __future__ import annotations

import copy
from pathlib import Path

from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="state-sync-aux-branch-reset",
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


def _seed_stale_attestation(ex: WeAllExecutor) -> str:
    env = {
        "tx_type": "BLOCK_ATTEST",
        "chain_id": ex.chain_id,
        "signer": "@discarded-validator",
        "nonce": 1,
        "payload": {
            "block_id": "discarded-branch-block",
            "validator": "@discarded-validator",
            "height": 1,
            "round": 0,
        },
        "block_id": "discarded-branch-block",
    }
    added = ex._att_pool.add(env)
    assert added["ok"] is True
    return str(added["att_id"])


class _SyncPeer:
    def __init__(self, source: WeAllExecutor) -> None:
        self.source = source

    def request_state_sync(self, _peer_id, req, **_kwargs):
        return self.source._state_sync_service().handle_request(req)


def test_checkpoint_sync_purges_aux_attestation_pool_and_restart_stays_clean(
    tmp_path: Path,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    _seed_stale_attestation(lagger)

    assert lagger._att_pool.size() == 1
    assert lagger._att_pool.fetch_for_block("discarded-branch-block")

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

    assert lagger._att_pool.size() == 0
    assert lagger._att_pool.fetch_for_block("discarded-branch-block") == []

    restarted = _make_executor(tmp_path, "lagger")
    assert restarted._att_pool.size() == 0
    assert restarted._att_pool.fetch_for_block("discarded-branch-block") == []


def test_restart_upgrades_old_bft_only_checkpoint_marker_and_purges_attestations(
    tmp_path: Path,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    _seed_stale_attestation(lagger)

    snapshot = copy.deepcopy(source.state)
    snapshot.pop("bft", None)
    checkpoint = source.get_latest_block()
    assert isinstance(checkpoint, dict)
    lagger._ledger_store.install_state_sync_checkpoint(
        state=snapshot,
        checkpoint_block=checkpoint,
    )
    checkpoint_hash = lagger._ledger_checkpoint_block_hash()
    assert checkpoint_hash

    # Simulate a node that previously ran the BFT-only checkpoint-reset repair:
    # the old marker matches the canonical checkpoint, but no versioned
    # auxiliary-branch reset has ever cleared the attestation pool.
    with lagger._aux_db.write_tx() as con:
        con.execute(
            "INSERT INTO meta(key, value) VALUES('state_sync_bft_reset_checkpoint_hash', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
            (checkpoint_hash,),
        )
        con.execute("DELETE FROM meta WHERE key='state_sync_aux_branch_reset_version';")

    assert lagger._att_pool.size() == 1

    restarted = _make_executor(tmp_path, "lagger")
    assert restarted._att_pool.size() == 0
    with restarted._aux_db.connection() as con:
        row = con.execute(
            "SELECT value FROM meta WHERE key='state_sync_aux_branch_reset_version' LIMIT 1;"
        ).fetchone()
    assert row is not None
    assert str(row["value"] or "") == "2"


def test_advancing_checkpoint_cannot_reuse_old_helper_height_journal(tmp_path: Path) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)

    old_next_height = int(lagger.state.get("height") or 0) + 1
    old_path = Path(lagger._helper_lane_journal_path(block_height=old_next_height))
    old_path.write_text("discarded-branch-helper-journal\n", encoding="utf-8")

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

    new_next_height = int(lagger.state.get("height") or 0) + 1
    assert new_next_height > old_next_height
    assert lagger._helper_lane_journal_path(block_height=new_next_height) != str(old_path)
    # Old files are currently harmless orphaned local evidence rather than
    # restart authority because journals are addressed by monotonically
    # advancing canonical block height. Do not delete them here: an explicitly
    # shared WEALL_HELPER_LANE_JOURNAL_DIR may not be owned exclusively by this
    # executor.
    assert old_path.exists()
