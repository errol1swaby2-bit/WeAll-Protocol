from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

import weall.runtime.bft_runtime_adapter as bft_adapter
from weall.runtime.block_hash import compute_block_hash
from weall.runtime.block_id import compute_block_id
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _executor(tmp_path: Path, name: str = "node", *, chain_id: str = "pb001bn") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.sqlite"),
        chain_id=chain_id,
        node_id=f"@{name}",
        tx_index_path="generated/tx_index.json",
    )


def _canonical_block(
    *,
    chain_id: str,
    proposer: str,
    state_root: str,
    prev_block_id: str = "missing-parent",
    prev_block_hash: str = "11" * 32,
    height: int = 2,
    ts_ms: int = 2000,
    receipts_root: str = "22" * 32,
) -> dict:
    header = {
        "chain_id": chain_id,
        "height": int(height),
        "prev_block_hash": prev_block_hash,
        "block_ts_ms": int(ts_ms),
        "tx_ids": [],
        "receipts_root": receipts_root,
        "state_root": state_root,
    }
    block_hash = compute_block_hash(header=header)
    block_id = compute_block_id(
        chain_id=chain_id,
        height=int(height),
        prev_block_id=prev_block_id,
        prev_block_hash=prev_block_hash,
        ts_ms=int(ts_ms),
        node_id=proposer,
        tx_ids=[],
        receipts_root=receipts_root,
    )
    return {
        "chain_id": chain_id,
        "block_id": block_id,
        "block_hash": block_hash,
        "height": int(height),
        "prev_block_id": prev_block_id,
        "block_ts_ms": int(ts_ms),
        "proposer": proposer,
        "header": header,
        "txs": [],
        "receipts": [],
    }


def test_same_block_id_different_canonical_hash_quarantine_survives_restart(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-id")
    first = _canonical_block(chain_id="pb001bn-id", proposer="v1", state_root="aa" * 32)
    second = _canonical_block(chain_id="pb001bn-id", proposer="v1", state_root="bb" * 32)
    assert first["block_id"] == second["block_id"]
    assert first["block_hash"] != second["block_hash"]

    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is True
    # Raw fetch conflicts are reject-only. This call models the same canonical
    # identity after an authenticated proposal/commit path has admitted it.
    assert ex._block_identity_conflicts(second, record_conflicts=True) is True
    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is False
    before = ex.bft_diagnostics()
    assert before["conflicted_block_ids"] == [first["block_id"]]

    restarted = _executor(tmp_path, chain_id="pb001bn-id")
    after = restarted.bft_diagnostics()
    assert after["conflicted_block_ids"] == [first["block_id"]]
    assert after["pending_remote_blocks_count"] == 0
    assert restarted.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is False
    assert (
        restarted.bft_cache_remote_block(second, expected_block_hash=second["block_hash"]) is False
    )


def test_same_canonical_hash_different_block_ids_quarantine_survives_restart(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-hash")
    first = _canonical_block(
        chain_id="pb001bn-hash",
        proposer="v1",
        state_root="aa" * 32,
        prev_block_id="parent-a",
    )
    second = _canonical_block(
        chain_id="pb001bn-hash",
        proposer="v1",
        state_root="aa" * 32,
        prev_block_id="parent-b",
    )
    assert first["block_id"] != second["block_id"]
    assert first["block_hash"] == second["block_hash"]

    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is True
    assert ex._block_identity_conflicts(second, record_conflicts=True) is True
    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is False
    before = ex.bft_diagnostics()
    assert before["conflicted_block_hashes"] == [first["block_hash"]]

    restarted = _executor(tmp_path, chain_id="pb001bn-hash")
    after = restarted.bft_diagnostics()
    assert after["conflicted_block_hashes"] == [first["block_hash"]]
    assert after["pending_remote_blocks_count"] == 0
    assert restarted.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is False
    assert (
        restarted.bft_cache_remote_block(second, expected_block_hash=second["block_hash"]) is False
    )


def test_canonical_looking_raw_fetch_conflict_is_reject_only_and_not_durable(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-fetch")
    first = _canonical_block(chain_id="pb001bn-fetch", proposer="v1", state_root="aa" * 32)
    second = _canonical_block(chain_id="pb001bn-fetch", proposer="v1", state_root="bb" * 32)
    assert first["block_id"] == second["block_id"]

    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is True
    assert ex.bft_cache_remote_block(second, expected_block_hash=second["block_hash"]) is False
    assert ex.bft_diagnostics()["conflicted_block_ids_count"] == 0

    restarted = _executor(tmp_path, chain_id="pb001bn-fetch")
    assert restarted.bft_diagnostics()["conflicted_block_ids_count"] == 0
    assert restarted.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is True


def test_malformed_advertised_hash_alias_rejects_without_poisoning_quarantine(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-alias")
    ex.state["blocks"] = {
        "known-id": {
            "height": 1,
            "prev_block_id": "",
            "block_ts_ms": 1000,
            "block_hash": "known-hash",
        }
    }
    forged = _canonical_block(
        chain_id="pb001bn-alias",
        proposer="attacker",
        state_root="aa" * 32,
        prev_block_id="known-id",
        prev_block_hash="known-hash",
    )
    forged["block_hash"] = "known-hash"
    assert compute_block_hash(header=forged["header"]) != forged["block_hash"]

    assert ex.bft_cache_remote_block(forged, expected_block_hash=forged["block_hash"]) is False
    diag = ex.bft_diagnostics()
    assert diag["conflicted_block_ids_count"] == 0
    assert diag["conflicted_block_hashes_count"] == 0
    assert ex._is_conflicted_block_hash("known-hash") is False


def test_unauthenticated_conflicting_proposal_does_not_create_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-proposal")
    first = _canonical_block(chain_id="pb001bn-proposal", proposer="v1", state_root="aa" * 32)
    second = _canonical_block(chain_id="pb001bn-proposal", proposer="v1", state_root="bb" * 32)
    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is True

    second["view"] = 1
    second["proposer_sig"] = "invalid"
    second["proposer_pubkey"] = "invalid"
    monkeypatch.setattr(bft_adapter, "verify_proposal_json", lambda **_kwargs: False)

    assert ex.bft_on_proposal(second) is None
    diag = ex.bft_diagnostics()
    assert diag["conflicted_block_ids_count"] == 0


def test_unverified_qc_cannot_create_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-qc")
    called = {"identity": False}

    monkeypatch.setattr(ex, "_bft_phase_allows_artifact_processing", lambda: True)
    monkeypatch.setattr(ex, "_bft_payload_phase_matches_current_security_model", lambda _q: True)
    monkeypatch.setattr(ex, "_bft_epoch_binding_matches", lambda _q: True)
    monkeypatch.setattr(ex, "_active_validators", lambda: [])
    monkeypatch.setattr(ex, "_validator_pubkeys", lambda: {})
    monkeypatch.setattr(bft_adapter, "verify_qc", lambda **_kwargs: False)

    def _identity(_qc: dict, *, source: str = "qc") -> bool:
        called["identity"] = True
        return False

    monkeypatch.setattr(ex, "_qc_identity_conflicts", _identity)
    qc = {
        "t": "QC",
        "chain_id": "pb001bn-qc",
        "view": 1,
        "block_id": "block-a",
        "block_hash": "hash-a",
        "parent_id": "",
        "votes": [],
    }
    assert ex.bft_verify_qc_json(qc) is None
    assert called["identity"] is False


def test_conflict_marker_persistence_failure_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-persist")

    @contextmanager
    def _broken_write_tx():
        raise RuntimeError("disk unavailable")
        yield  # pragma: no cover

    monkeypatch.setattr(ex._aux_db, "write_tx", _broken_write_tx)
    with pytest.raises(ExecutorError, match="bft_conflict_quarantine_persist_failed"):
        ex._mark_block_id_conflict(
            block_id="conflicted",
            known_hash="aa" * 32,
            new_hash="bb" * 32,
            source="test",
        )
    assert ex._is_conflicted_block_id("conflicted") is True


def test_checkpoint_branch_reset_clears_durable_conflict_quarantine(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-reset")
    ex._mark_block_id_conflict(
        block_id="conflicted",
        known_hash="aa" * 32,
        new_hash="bb" * 32,
        source="test",
    )
    assert ex._is_conflicted_block_id("conflicted") is True

    ex._reset_bft_branch_state_for_checkpoint(checkpoint_hash="cc" * 32)
    assert ex._is_conflicted_block_id("conflicted") is False

    restarted = _executor(tmp_path, chain_id="pb001bn-reset")
    assert restarted._is_conflicted_block_id("conflicted") is False
    with restarted._aux_db.connection() as con:
        count = con.execute(
            "SELECT COUNT(*) FROM bft_pending_artifacts "
            "WHERE kind IN ('conflicted_block_id','conflicted_block_hash');"
        ).fetchone()[0]
    assert int(count) == 0


def test_durable_conflict_marker_dominates_stale_pending_row_after_failed_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-stale-row")
    first = _canonical_block(chain_id="pb001bn-stale-row", proposer="v1", state_root="aa" * 32)
    second = _canonical_block(chain_id="pb001bn-stale-row", proposer="v1", state_root="bb" * 32)
    assert ex.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is True

    # Simulate the historical best-effort auxiliary delete failing after the
    # authenticated conflict marker itself has become durable.
    monkeypatch.setattr(ex, "_delete_pending_bft_artifact", lambda **_kwargs: None)
    assert ex._block_identity_conflicts(second, record_conflicts=True) is True
    assert ex._is_conflicted_block_id(first["block_id"]) is True

    restarted = _executor(tmp_path, chain_id="pb001bn-stale-row")
    diag = restarted.bft_diagnostics()
    assert diag["conflicted_block_ids"] == [first["block_id"]]
    assert diag["pending_remote_blocks_count"] == 0
    assert restarted.bft_cache_remote_block(first, expected_block_hash=first["block_hash"]) is False


def test_corrupt_durable_conflict_marker_fails_restart_closed(tmp_path: Path) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-corrupt")
    with ex._aux_db.write_tx() as con:
        con.execute(
            "INSERT OR REPLACE INTO bft_pending_artifacts"
            "(kind, block_id, block_hash, payload_json, created_ms, updated_ms) "
            "VALUES(?,?,?,?,?,?);",
            ("conflicted_block_id", "bad", "", "{not-json", 1, 1),
        )

    with pytest.raises(ExecutorError, match="bft_conflict_quarantine_corrupt"):
        _executor(tmp_path, chain_id="pb001bn-corrupt")


def test_generic_block_replay_checks_identity_without_recording_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _executor(tmp_path, chain_id="pb001bn-replay")
    block = _canonical_block(
        chain_id="pb001bn-replay",
        proposer="v1",
        state_root="aa" * 32,
        prev_block_id="",
        prev_block_hash="",
        height=1,
        ts_ms=1000,
    )
    observed: dict[str, bool] = {}

    def _identity(_block: dict, *, record_conflicts: bool = True) -> bool:
        observed["record_conflicts"] = bool(record_conflicts)
        return True

    monkeypatch.setattr(ex, "_block_identity_conflicts", _identity)
    meta = ex.apply_block(block)
    assert meta.ok is False
    assert meta.error == "bad_block:block_id_hash_conflict"
    assert observed == {"record_conflicts": False}


def test_authenticated_conflicting_qc_quarantine_survives_restart_exact_crypto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    from weall.crypto.sig import sign_mldsa
    from weall.runtime.bft_hotstuff import BftVote, canonical_vote_message

    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    validators = ["v1", "v2", "v3", "v4"]
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for validator in validators:
        sk = mldsa.MLDSA65PrivateKey.generate()
        pubs[validator] = sk.public_key().public_bytes_raw().hex()
        privs[validator] = sk.private_bytes_raw().hex()

    ex = _executor(tmp_path, chain_id="pb001bn-auth-qc")
    state = ex.state
    state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    consensus = state.setdefault("consensus", {})
    consensus.setdefault("phase", {})["current"] = "bft_active"
    registry = consensus.setdefault("validators", {}).setdefault("registry", {})
    for validator in validators:
        registry[validator] = {"status": "active", "pubkey": pubs[validator]}
    consensus.setdefault("epochs", {})["current"] = 4
    validator_set = consensus.setdefault("validator_set", {})
    validator_set["active_set"] = list(validators)
    validator_set["epoch"] = 4
    ex._ledger_store.write(state)
    ex.state = ex._ledger_store.read()
    ex.state["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex._ledger_store.write(ex.state)
    ex.state = ex._ledger_store.read()
    set_hash = ex._current_validator_set_hash()

    def _qc(block_hash: str, view: int) -> dict:
        votes = []
        for signer in validators[:3]:
            message = canonical_vote_message(
                chain_id="pb001bn-auth-qc",
                view=view,
                block_id="block-conflict",
                block_hash=block_hash,
                parent_id="genesis",
                signer=signer,
                validator_epoch=4,
                validator_set_hash=set_hash,
            )
            votes.append(
                BftVote(
                    chain_id="pb001bn-auth-qc",
                    view=view,
                    block_id="block-conflict",
                    block_hash=block_hash,
                    parent_id="genesis",
                    signer=signer,
                    pubkey=pubs[signer],
                    sig=sign_mldsa(
                        message=message,
                        privkey=privs[signer],
                        encoding="hex",
                    ),
                    validator_epoch=4,
                    validator_set_hash=set_hash,
                ).to_json()
            )
        return {
            "t": "QC",
            "chain_id": "pb001bn-auth-qc",
            "view": view,
            "block_id": "block-conflict",
            "block_hash": block_hash,
            "parent_id": "genesis",
            "votes": votes,
            "validator_epoch": 4,
            "validator_set_hash": set_hash,
        }

    assert ex.bft_on_qc(_qc("aa" * 32, 7)) is None
    assert ex.bft_on_qc(_qc("bb" * 32, 8)) is None
    assert ex._is_conflicted_block_id("block-conflict") is True

    restarted = _executor(tmp_path, chain_id="pb001bn-auth-qc")
    assert restarted._is_conflicted_block_id("block-conflict") is True
    assert restarted.bft_diagnostics()["pending_missing_qcs_count"] == 0
