from __future__ import annotations

from pathlib import Path

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _mk_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=name,
        chain_id="weall-test",
        tx_index_path=str(Path("generated/tx_index.json")),
    )


def _signed(ex: WeAllExecutor, *, signer: str, nonce: int, tx_type: str, payload: dict, priv_hex: str) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "chain_id": ex.chain_id,
    }
    return sign_tx_envelope_dict(tx=tx, privkey=priv_hex)


def test_failed_block_apply_does_not_consume_nonce_batch37(tmp_path: Path) -> None:
    signer = "@user000"
    pub, priv = deterministic_ed25519_keypair(label=signer)
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

    block1, state1, applied1, invalid1, err1 = leader.build_block_candidate(max_txs=10, allow_empty=False)
    assert err1 == ""
    meta1 = leader.commit_block_candidate(block=block1, new_state=state1, applied_ids=applied1, invalid_ids=invalid1)
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
    assert leader.submit_tx(fail_tx)["ok"] is True

    block2, state2, _applied2, invalid2, err2 = leader.build_block_candidate(max_txs=10, allow_empty=False)
    assert err2 == ""
    assert isinstance(block2, dict)
    assert len(invalid2) == 1
    receipts = block2.get("receipts") or []
    assert len(receipts) == 1
    assert receipts[0]["tx_type"] == "ACCOUNT_DEVICE_REVOKE"
    assert receipts[0]["ok"] is False
    assert state2["accounts"][signer]["nonce"] == 1

    follower = _mk_executor(tmp_path, "follower")
    meta2 = follower.apply_block(dict(block1))
    assert meta2.ok is True
    assert follower.state["accounts"][signer]["nonce"] == 1

    meta3 = follower.apply_block(dict(block2))
    assert meta3.ok is True
    assert follower.state["accounts"][signer]["nonce"] == 1
