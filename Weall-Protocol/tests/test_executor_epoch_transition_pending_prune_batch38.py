from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_hotstuff import validator_set_hash
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_validator_state(
    ex: WeAllExecutor,
    validators: list[str],
    pubs: dict[str, str],
    *,
    epoch: int,
) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = int(epoch)
    c["validator_set"]["set_hash"] = validator_set_hash(list(validators))
    ex.state = st
    ex._bft.load_from_state(ex.state)


def _mk_executor(tmp_path: Path) -> tuple[WeAllExecutor, dict[str, str]]:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="v1",
        chain_id="bft-live",
        tx_index_path=str(Path("generated/tx_index.json")),
    )
    pubs: dict[str, str] = {}
    for vid in ("v1", "v2", "v3", "v4", "v5"):
        pub, _sk = deterministic_ed25519_keypair(label=vid)
        pubs[vid] = pub
    return ex, pubs


def test_epoch_transition_immediately_prunes_stale_pending_fetch_and_remote_artifacts(
    tmp_path: Path,
) -> None:
    ex, pubs = _mk_executor(tmp_path)
    old_validators = ["v1", "v2", "v3", "v4"]
    new_validators = ["v2", "v3", "v4", "v5"]
    _seed_validator_state(ex, old_validators, pubs, epoch=3)

    old_set_hash = ex._current_validator_set_hash()
    ex._pending_missing_qcs["old-epoch-block"] = {
        "t": "QC",
        "chain_id": ex.chain_id,
        "view": 7,
        "block_id": "old-epoch-block",
        "block_hash": "old-hash",
        "parent_id": "genesis",
        "votes": [],
        "validator_epoch": 3,
        "validator_set_hash": old_set_hash,
    }
    ex._pending_remote_blocks["old-epoch-block"] = {
        "block_id": "old-epoch-block",
        "prev_block_id": "genesis",
        "height": 1,
        "view": 7,
        "validator_epoch": 3,
        "validator_set_hash": old_set_hash,
        "header": {
            "chain_id": ex.chain_id,
            "height": 1,
            "prev_block_hash": "00" * 32,
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "11" * 32,
            "state_root": "22" * 32,
        },
        "txs": [],
        "receipts": [],
    }

    _seed_validator_state(ex, new_validators, pubs, epoch=4)
    changed = ex._prune_pending_bft_artifacts_on_local_validator_transition(
        previous_epoch=3,
        previous_set_hash=old_set_hash,
    )

    assert changed is True
    assert ex.bft_pending_fetch_requests() == []
    assert "old-epoch-block" not in ex._pending_missing_qcs
    assert "old-epoch-block" not in ex._pending_remote_blocks


def test_epoch_transition_prunes_only_stale_epoch_artifacts_and_keeps_current_epoch_entries(
    tmp_path: Path,
) -> None:
    ex, pubs = _mk_executor(tmp_path)
    old_validators = ["v1", "v2", "v3", "v4"]
    new_validators = ["v2", "v3", "v4", "v5"]
    _seed_validator_state(ex, old_validators, pubs, epoch=3)

    old_set_hash = ex._current_validator_set_hash()
    ex._pending_missing_qcs["stale-block"] = {
        "t": "QC",
        "chain_id": ex.chain_id,
        "view": 3,
        "block_id": "stale-block",
        "block_hash": "stale-hash",
        "parent_id": "genesis",
        "votes": [],
        "validator_epoch": 3,
        "validator_set_hash": old_set_hash,
    }

    _seed_validator_state(ex, new_validators, pubs, epoch=4)
    new_set_hash = ex._current_validator_set_hash()
    ex._pending_missing_qcs["current-block"] = {
        "t": "QC",
        "chain_id": ex.chain_id,
        "view": 4,
        "block_id": "current-block",
        "block_hash": "current-hash",
        "parent_id": "genesis",
        "votes": [],
        "validator_epoch": 4,
        "validator_set_hash": new_set_hash,
    }
    ex._pending_remote_blocks["current-block"] = {
        "block_id": "current-block",
        "prev_block_id": "genesis",
        "height": 1,
        "view": 4,
        "validator_epoch": 4,
        "validator_set_hash": new_set_hash,
        "header": {
            "chain_id": ex.chain_id,
            "height": 1,
            "prev_block_hash": "00" * 32,
            "block_ts_ms": 1001,
            "tx_ids": [],
            "receipts_root": "11" * 32,
            "state_root": "22" * 32,
        },
        "txs": [],
        "receipts": [],
    }

    changed = ex._prune_pending_bft_artifacts_on_local_validator_transition(
        previous_epoch=3,
        previous_set_hash=old_set_hash,
    )

    assert changed is True
    assert "stale-block" not in ex._pending_missing_qcs
    assert ex.bft_pending_fetch_requests() == []
    assert "current-block" in ex._pending_missing_qcs
    assert "current-block" in ex._pending_remote_blocks
