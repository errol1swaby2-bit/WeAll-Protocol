from __future__ import annotations

import copy
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from weall.net.messages import MsgType, TxEnvelopeMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime import executor as executor_module
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="pb001baj-mempool-canonical-height-atomicity",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _register_tx(signer: str) -> dict:
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": {"pubkey": f"k:{signer}"},
    }


def _produce_register_block(ex: WeAllExecutor, signer: str) -> None:
    result = ex.submit_tx(_register_tx(signer))
    assert result["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


def _advance_source(source: WeAllExecutor) -> None:
    for signer in ("@race", "@u2", "@u3"):
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


def test_persistent_mempool_rejects_stale_admission_height_after_checkpoint(
    tmp_path: Path,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    anchor = _force_snapshot_source(source)
    _sync_snapshot(lagger, source, anchor)
    assert int(lagger.state.get("height") or 0) == 3

    one = lagger._mempool.add(_register_tx("@stale-one"), current_height=0)
    many = lagger._mempool.add_many([_register_tx("@stale-two")], current_height=0)

    assert one["ok"] is False
    assert one["error"] == "mempool_stale_admission_height"
    assert many == [
        {
            "ok": False,
            "error": "mempool_stale_admission_height",
            "details": {"admitted_at_height": 0, "durable_height": 3},
        }
    ]
    assert lagger._mempool.size() == 0


def test_submit_tx_cannot_publish_old_branch_admission_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    anchor = _force_snapshot_source(source)

    admitted = threading.Event()
    release_admission = threading.Event()
    submit_done = threading.Event()
    sync_done = threading.Event()
    errors: list[BaseException] = []
    result: list[dict] = []

    original_admit = executor_module.admit_tx

    def _blocked_admit(*args, **kwargs):
        verdict = original_admit(*args, **kwargs)
        if bool(getattr(verdict, "ok", False)):
            admitted.set()
            assert release_admission.wait(timeout=5.0)
        return verdict

    monkeypatch.setattr(executor_module, "admit_tx", _blocked_admit)

    def _submit() -> None:
        try:
            result.append(lagger.submit_tx(_register_tx("@race")))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            submit_done.set()

    def _sync() -> None:
        try:
            _sync_snapshot(lagger, source, anchor)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            sync_done.set()

    submitter = threading.Thread(target=_submit, daemon=True)
    submitter.start()
    assert admitted.wait(timeout=5.0)

    syncer = threading.Thread(target=_sync, daemon=True)
    syncer.start()
    assert sync_done.wait(timeout=5.0)
    assert int(lagger.state.get("height") or 0) == 3

    release_admission.set()
    assert submit_done.wait(timeout=5.0)
    submitter.join(timeout=1.0)
    syncer.join(timeout=1.0)

    assert errors == []
    assert result == [
        {
            "ok": False,
            "error": "mempool_stale_admission_height",
            "details": {"admitted_at_height": 0, "durable_height": 3},
        }
    ]
    assert lagger._mempool.size() == 0


def test_submit_tx_cannot_reinsert_transaction_after_winning_block_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _make_executor(tmp_path, "node")
    tx = _register_tx("@alice")
    first = ex.submit_tx(copy.deepcopy(tx))
    assert first["ok"] is True
    assert ex._mempool.size() == 1

    admitted = threading.Event()
    release_admission = threading.Event()
    submit_done = threading.Event()
    errors: list[BaseException] = []
    result: list[dict] = []

    original_admit = executor_module.admit_tx

    def _blocked_admit(*args, **kwargs):
        verdict = original_admit(*args, **kwargs)
        if bool(getattr(verdict, "ok", False)):
            admitted.set()
            assert release_admission.wait(timeout=5.0)
        return verdict

    monkeypatch.setattr(executor_module, "admit_tx", _blocked_admit)

    def _submit() -> None:
        try:
            result.append(ex.submit_tx(copy.deepcopy(tx)))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            submit_done.set()

    submitter = threading.Thread(target=_submit, daemon=True)
    submitter.start()
    assert admitted.wait(timeout=5.0)

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    assert int(ex.state.get("height") or 0) == 1
    assert ex._mempool.size() == 0

    release_admission.set()
    assert submit_done.wait(timeout=5.0)
    submitter.join(timeout=1.0)

    assert errors == []
    assert result == [
        {
            "ok": False,
            "error": "mempool_stale_admission_height",
            "details": {"admitted_at_height": 0, "durable_height": 1},
        }
    ]
    assert ex._mempool.size() == 0


def test_network_tx_ingress_cannot_repopulate_mempool_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    anchor = _force_snapshot_source(source)

    loop = NetMeshLoop(
        executor=lagger,
        mempool=lagger._mempool,
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )

    admitted = threading.Event()
    release_admission = threading.Event()
    ingress_done = threading.Event()
    sync_done = threading.Event()
    errors: list[BaseException] = []

    monkeypatch.setattr("weall.net.net_loop.verify_tx_signature", lambda _state, _tx: True)

    def _blocked_admit(**_kwargs):
        admitted.set()
        assert release_admission.wait(timeout=5.0)
        return SimpleNamespace(ok=True, code=None)

    monkeypatch.setattr("weall.net.net_loop.admit_tx", _blocked_admit)

    tx = _register_tx("@race")
    tx["chain_id"] = lagger.chain_id
    msg = TxEnvelopeMsg(
        header=WireHeader(
            type=MsgType.TX_ENVELOPE,
            chain_id=lagger.chain_id,
            schema_version="1",
            tx_index_hash="",
        ),
        nonce=1,
        tx=tx,
    )

    def _ingress() -> None:
        try:
            loop._on_tx("peer1", msg)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            ingress_done.set()

    def _sync() -> None:
        try:
            _sync_snapshot(lagger, source, anchor)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            sync_done.set()

    ingress = threading.Thread(target=_ingress, daemon=True)
    ingress.start()
    assert admitted.wait(timeout=5.0)

    syncer = threading.Thread(target=_sync, daemon=True)
    syncer.start()
    assert sync_done.wait(timeout=5.0)
    assert int(lagger.state.get("height") or 0) == 3

    release_admission.set()
    assert ingress_done.wait(timeout=5.0)
    ingress.join(timeout=1.0)
    syncer.join(timeout=1.0)

    assert errors == []
    assert lagger._mempool.size() == 0
