from __future__ import annotations

import sqlite3
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


def test_commit_failure_surfaces_real_error_class(tmp_path: Path) -> None:
    """
    A forced write-path failure should surface the concrete exception class
    in executor meta.error, rather than collapsing into an opaque failure.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="commit-failure-shape",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(_signed_account_register(chain_id="commit-failure-shape", signer="@user0"))
    assert sub["ok"] is True

    original_write_tx = ex._db.write_tx

    @contextmanager
    def broken_write_tx():
        raise sqlite3.OperationalError("forced commit failure for test")
        yield  # pragma: no cover

    ex._db.write_tx = broken_write_tx  # type: ignore[assignment]
    try:
        meta = ex.produce_block(max_txs=1)
    finally:
        ex._db.write_tx = original_write_tx  # type: ignore[assignment]

    assert meta.ok is False
    assert isinstance(meta.error, str)
    assert "commit_failed" in meta.error
    assert "OperationalError" in meta.error
    assert "forced commit failure for test" in meta.error


def test_commit_failure_does_not_advance_height(tmp_path: Path) -> None:
    """
    A failed commit must not partially advance chain height.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="commit-failure-height",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(_signed_account_register(chain_id="commit-failure-height", signer="@user0"))
    assert sub["ok"] is True

    before = ex.read_state()
    assert int(before["height"]) == 0

    original_write_tx = ex._db.write_tx

    @contextmanager
    def broken_write_tx():
        raise sqlite3.OperationalError("forced commit failure for test")
        yield  # pragma: no cover

    ex._db.write_tx = broken_write_tx  # type: ignore[assignment]
    try:
        meta = ex.produce_block(max_txs=1)
    finally:
        ex._db.write_tx = original_write_tx  # type: ignore[assignment]

    assert meta.ok is False

    after = ex.read_state()
    assert int(after["height"]) == 0
    assert str(after["tip"]) == str(before["tip"])
