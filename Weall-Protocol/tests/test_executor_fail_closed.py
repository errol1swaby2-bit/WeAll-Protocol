from __future__ import annotations

from pathlib import Path

import pytest

import weall.runtime.executor as executor_mod
from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.domain_apply import NonceSideEffectError
from weall.runtime.executor import WeAllExecutor
from weall.runtime.system_tx_engine import (
    SystemQueueCorruptionError,
    prune_emitted_system_queue,
    system_queue_phase_for_id,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


def _mk_executor(tmp_path: Path, name: str = "node") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id="weall-test",
        tx_index_path=str(Path("generated/tx_index.json")),
    )


def _submit_register(ex: WeAllExecutor, signer: str = "@user000") -> None:
    pubkey, priv = deterministic_ed25519_keypair(label=signer)
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": {"pubkey": pubkey},
        "chain_id": ex.chain_id,
    }
    signed = sign_tx_envelope_dict(tx=tx, privkey=priv.private_bytes_raw().hex())
    sub = ex.submit_tx(signed)
    assert sub["ok"] is True


def test_prod_build_block_candidate_fails_closed_on_nonce_side_effect_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _mk_executor(tmp_path, "leader")
    _submit_register(ex)

    def boom(*args, **kwargs):
        raise NonceSideEffectError("boom")

    monkeypatch.setattr(executor_mod, "apply_tx_atomic_meta", boom)

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=10, allow_empty=False
    )

    assert block is None
    assert new_state is None
    assert applied_ids == []
    assert invalid_ids == []
    assert err == "tx_apply_failed:NonceSideEffectError"


def test_prod_apply_block_fails_closed_on_nonce_side_effect_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    leader = _mk_executor(tmp_path, "leader")
    _submit_register(leader)
    block, _new_state, _applied_ids, _invalid_ids, err = leader.build_block_candidate(
        max_txs=10, allow_empty=False
    )
    assert err == ""
    assert isinstance(block, dict)

    follower = _mk_executor(tmp_path, "follower")

    def boom(*args, **kwargs):
        raise NonceSideEffectError("boom")

    monkeypatch.setattr(executor_mod, "apply_tx_atomic_meta", boom)

    meta = follower.apply_block(dict(block))

    assert meta.ok is False
    assert meta.error == "bad_block:tx_apply_failed:NonceSideEffectError"


def test_prod_commit_block_candidate_fails_closed_on_corrupt_system_queue_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    ex = _mk_executor(tmp_path, "leader")

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)

    new_state["system_queue"] = ["corrupt"]
    meta = ex.commit_block_candidate(
        block=block, new_state=new_state, applied_ids=applied_ids, invalid_ids=invalid_ids
    )

    assert meta.ok is False
    assert meta.error == "system_queue_prune_failed:SystemQueueCorruptionError"


def test_system_queue_helpers_fail_closed_on_corrupt_entries() -> None:
    state = {"system_queue": ["corrupt"]}

    with pytest.raises(SystemQueueCorruptionError):
        prune_emitted_system_queue(state)

    with pytest.raises(SystemQueueCorruptionError):
        system_queue_phase_for_id(state, queue_id="qid")
