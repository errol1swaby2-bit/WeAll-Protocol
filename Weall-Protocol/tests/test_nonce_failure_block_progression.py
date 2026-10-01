from __future__ import annotations

from pathlib import Path

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.testing.sigtools import deterministic_mldsa_keypair


def _mk_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id="weall-test",
        tx_index_path=str(Path("generated/tx_index.json")),
    )


def _signed(
    ex: WeAllExecutor, *, signer: str, nonce: int, tx_type: str, payload: dict, priv_hex: str
) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "chain_id": ex.chain_id,
    }
    return sign_tx_envelope_dict(tx=tx, privkey=priv_hex)


def _assert_replay_rejected(result: dict) -> None:
    assert result.get("ok") is False or result.get("already_known") is True, result


def test_failed_block_apply_consumes_nonce_and_rejects_replay_across_restart(
    tmp_path: Path,
) -> None:
    """A02-F001/A16-F002: a failed canonical inclusion is a one-shot signed identity."""

    signer = "@user000"
    pub, priv = deterministic_mldsa_keypair(label=signer)
    priv_hex = priv.private_bytes_raw().hex()

    leader = _mk_executor(tmp_path, "leader")
    register = _signed(
        leader,
        signer=signer,
        nonce=1,
        tx_type="ACCOUNT_REGISTER",
        payload={"pubkey": pub},
        priv_hex=priv_hex,
    )
    assert leader.submit_tx(register)["ok"] is True

    block1, state1, applied1, invalid1, err1 = leader.build_block_candidate(
        max_txs=10, allow_empty=False
    )
    assert err1 == ""
    assert isinstance(block1, dict)
    assert isinstance(state1, dict)
    meta1 = leader.commit_block_candidate(
        block=block1, new_state=state1, applied_ids=applied1, invalid_ids=invalid1
    )
    assert meta1.ok is True
    assert leader.state["accounts"][signer]["nonce"] == 1

    fail_tx = _signed(
        leader,
        signer=signer,
        nonce=2,
        tx_type="ACCOUNT_DEVICE_REVOKE",
        payload={"device_id": "missing"},
        priv_hex=priv_hex,
    )
    submitted = leader.submit_tx(fail_tx)
    assert submitted["ok"] is True
    failed_tx_id = str(submitted["tx_id"])

    block2, state2, applied2, invalid2, err2 = leader.build_block_candidate(
        max_txs=10, allow_empty=False
    )
    assert err2 == ""
    assert isinstance(block2, dict)
    assert isinstance(state2, dict)
    assert len(invalid2) == 1
    receipts = block2.get("receipts") or []
    assert len(receipts) == 1
    assert receipts[0]["tx_id"] == failed_tx_id
    assert receipts[0]["tx_type"] == "ACCOUNT_DEVICE_REVOKE"
    assert receipts[0]["ok"] is False
    assert state2["accounts"][signer]["nonce"] == 2

    leader_meta2 = leader.commit_block_candidate(
        block=block2,
        new_state=state2,
        applied_ids=applied2,
        invalid_ids=invalid2,
    )
    assert leader_meta2.ok is True
    assert leader.state["accounts"][signer]["nonce"] == 2
    assert leader.get_tx_status(failed_tx_id)["status"] == "confirmed"
    _assert_replay_rejected(leader.submit_tx(fail_tx))

    follower = _mk_executor(tmp_path, "follower")
    follower_meta1 = follower.apply_block(dict(block1))
    assert follower_meta1.ok is True
    assert follower.state["accounts"][signer]["nonce"] == 1

    follower_meta2 = follower.apply_block(dict(block2))
    assert follower_meta2.ok is True
    assert follower.state["accounts"][signer]["nonce"] == 2
    assert follower.get_tx_status(failed_tx_id)["status"] == "confirmed"
    assert compute_state_root(follower.state) == compute_state_root(leader.state)
    _assert_replay_rejected(follower.submit_tx(fail_tx))

    restarted = _mk_executor(tmp_path, "follower")
    assert restarted.state["accounts"][signer]["nonce"] == 2
    assert restarted.get_tx_status(failed_tx_id)["status"] == "confirmed"
    assert compute_state_root(restarted.state) == compute_state_root(leader.state)
    _assert_replay_rejected(restarted.submit_tx(fail_tx))
