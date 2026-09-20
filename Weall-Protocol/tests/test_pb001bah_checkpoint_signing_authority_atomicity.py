from __future__ import annotations

import threading
from pathlib import Path

import pytest

from weall.net.state_sync import build_snapshot_anchor
from weall.runtime import bft_runtime_adapter
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="pb001bah-checkpoint-signing-authority",
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


def test_checkpoint_snapshot_rejects_local_timeout_signing_history(tmp_path: Path) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)

    # TIMEOUT is a locally signed HotStuff artifact too. Destructive snapshot
    # replacement must not erase its anti-replay / same-view emission cursor.
    lagger._bft.last_timeout_view = 7
    lagger._persist_bft_state()

    anchor = _force_snapshot_source(source)

    with pytest.raises(ExecutorError, match="state_sync_snapshot_local_signing_history_present"):
        lagger.request_and_apply_state_sync(
            _SyncPeer(source),
            "source",
            trusted_anchor=anchor,
            timeout_ms=100,
            sleep_ms=0,
        )

    assert lagger._bft.last_timeout_view == 7


def test_checkpoint_snapshot_guard_and_reset_are_atomic_against_concurrent_bft_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_executor(tmp_path, "source")
    lagger = _make_executor(tmp_path, "lagger")
    _advance_source(source)
    anchor = _force_snapshot_source(source)

    reset_entered = threading.Event()
    allow_reset = threading.Event()
    bft_done = threading.Event()
    sync_done = threading.Event()
    errors: list[BaseException] = []

    original_reset = lagger._reset_bft_branch_state_for_checkpoint

    def _blocked_reset(*, checkpoint_hash: str) -> None:
        # The signing-history guard has already passed when this is reached.
        reset_entered.set()
        assert allow_reset.wait(timeout=5.0)
        original_reset(checkpoint_hash=checkpoint_hash)

    monkeypatch.setattr(lagger, "_reset_bft_branch_state_for_checkpoint", _blocked_reset)

    def _simulated_authenticated_proposal(self, proposal):
        del proposal
        # Model the security-relevant result of successful proposal admission:
        # a local vote cursor has been created and durably recorded.
        assert self._bft.record_local_vote(
            view=7,
            block_id="race-vote",
            block_hash="77" * 32,
        )
        self._persist_bft_state()
        return {"t": "VOTE", "view": 7, "block_id": "race-vote"}

    monkeypatch.setattr(bft_runtime_adapter, "bft_on_proposal", _simulated_authenticated_proposal)

    def _sync() -> None:
        try:
            lagger.request_and_apply_state_sync(
                _SyncPeer(source),
                "source",
                trusted_anchor=anchor,
                timeout_ms=100,
                sleep_ms=0,
            )
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            sync_done.set()

    def _ingress() -> None:
        try:
            lagger.bft_on_proposal({"branch": "concurrent"})
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            bft_done.set()

    sync_thread = threading.Thread(target=_sync, daemon=True)
    sync_thread.start()
    assert reset_entered.wait(timeout=5.0)

    ingress_thread = threading.Thread(target=_ingress, daemon=True)
    ingress_thread.start()

    # The destructive checkpoint owns the branch lock from signing-history
    # inspection through reset/install/rebuild. Concurrent BFT signing therefore
    # cannot enter the old engine after the guard has already returned safe.
    assert bft_done.wait(timeout=0.15) is False

    allow_reset.set()

    assert sync_done.wait(timeout=5.0)
    assert bft_done.wait(timeout=5.0)
    sync_thread.join(timeout=1.0)
    ingress_thread.join(timeout=1.0)

    assert errors == []
    assert int(lagger.state.get("height") or 0) == int(source.state.get("height") or 0)

    # The proposal is processed only after checkpoint replacement and therefore
    # records its anti-equivocation cursor on the adopted branch's fresh engine.
    assert lagger._bft.last_voted_view == 7
    assert lagger._bft.last_voted_block_id == "race-vote"
    assert lagger._bft.last_voted_block_hash == "77" * 32
