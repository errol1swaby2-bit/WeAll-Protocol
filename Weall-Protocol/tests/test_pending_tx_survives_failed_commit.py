from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from weall.crypto.sig import canonical_tx_message
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _signed_account_register(*, chain_id: str, signer: str) -> dict[str, object]:
    pub, priv = deterministic_ed25519_keypair(label=signer)
    payload = {"pubkey": pub}
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": payload,
        "chain_id": chain_id,
        "sig": priv.sign(
            canonical_tx_message(
                chain_id=chain_id,
                tx_type="ACCOUNT_REGISTER",
                signer=signer,
                nonce=1,
                payload=payload,
                parent=None,
            )
        ).hex(),
    }


def test_pending_tx_survives_failed_commit(tmp_path: Path) -> None:
    """
    If commit fails after a tx is selected for block production, that tx must
    remain pending and not disappear from mempool.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="pending-survives-failed-commit",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(_signed_account_register(chain_id="pending-survives-failed-commit", signer="@user1"))
    assert sub["ok"] is True
    tx_id = sub["tx_id"]

    original_write_tx = ex._db.write_tx

    @contextmanager
    def broken_write_tx():
        with original_write_tx() as con:
            raise RuntimeError("forced_commit_failure_for_test")
            yield con

    ex._db.write_tx = broken_write_tx  # type: ignore[assignment]
    try:
        meta = ex.produce_block(max_txs=1)
    finally:
        ex._db.write_tx = original_write_tx  # type: ignore[assignment]

    assert meta.ok is False
    assert str(meta.error).startswith("commit_failed:RuntimeError")
    assert "forced_commit_failure_for_test" in str(meta.error)

    mp = ex.read_mempool()
    ids = {item["tx_id"] for item in mp}
    assert tx_id in ids

    st = ex.read_state()
    assert int(st["height"]) == 0
