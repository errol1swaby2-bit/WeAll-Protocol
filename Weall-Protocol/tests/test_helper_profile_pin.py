from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _register_account(ex: WeAllExecutor, signer: str) -> None:
    res = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert res["ok"] is True


def test_restart_rejects_helper_execution_profile_mismatch_batch111(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")
    monkeypatch.setenv("WEALL_HELPER_TIMEOUT_MS", "7000")

    db_path = str(tmp_path / "helper_profile.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch111-profile",
        tx_index_path=_tx_index_path(),
    )
    meta = ex.read_state().get("meta", {})
    assert meta.get("helper_execution_profile") == {
        "helper_mode_enabled": True,
        "helper_fast_path_enabled": True,
        "helper_timeout_ms": 7000,
        "enforce_helper_signature": True,
        "enforce_helper_certificate_consistency": True,
        "enforce_helper_tx_order_hash": True,
        "enforce_helper_namespace_hash": True,
        "enforce_helper_receipts_root": True,
    }
    assert isinstance(meta.get("helper_execution_profile_hash"), str)
    assert meta.get("helper_execution_profile_hash")

    monkeypatch.setenv("WEALL_HELPER_TIMEOUT_MS", "5000")
    with pytest.raises(ExecutorError, match="helper_execution_profile mismatch"):
        WeAllExecutor(
            db_path=db_path,
            node_id="@node",
            chain_id="batch111-profile",
            tx_index_path=_tx_index_path(),
        )



def test_startup_rejects_helper_fast_path_without_helper_mode_batch111(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.delenv("WEALL_HELPER_MODE_ENABLED", raising=False)
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    with pytest.raises(ExecutorError, match="helper fast path requires WEALL_HELPER_MODE_ENABLED=1"):
        WeAllExecutor(
            db_path=str(tmp_path / "helper_requires_mode.db"),
            node_id="@node",
            chain_id="batch111-requires-mode",
            tx_index_path=_tx_index_path(),
        )



def test_build_block_candidate_uses_pinned_helper_profile_when_runtime_profile_drifts_batch111(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")
    monkeypatch.setenv("WEALL_HELPER_TIMEOUT_MS", "5000")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_drift.db"),
        node_id="@node",
        chain_id="batch111-drift",
        tx_index_path=_tx_index_path(),
    )
    _register_account(ex, "@alice")

    meta = ex.state.setdefault("meta", {})
    meta["helper_execution_profile"] = {
        "helper_mode_enabled": True,
        "helper_fast_path_enabled": False,
        "helper_timeout_ms": 5000,
        "enforce_helper_signature": True,
        "enforce_helper_certificate_consistency": True,
        "enforce_helper_tx_order_hash": True,
        "enforce_helper_namespace_hash": True,
        "enforce_helper_receipts_root": True,
    }

    block, new_state, _applied_ids, _invalid_ids, err = ex.build_block_candidate(max_txs=10)
    assert err == ""
    assert block is not None
    assert isinstance(new_state, dict)
    helper_profile = (new_state.get("meta") or {}).get("helper_execution_profile")
    assert helper_profile == {
        "helper_mode_enabled": True,
        "helper_fast_path_enabled": False,
        "helper_timeout_ms": 5000,
        "enforce_helper_signature": True,
        "enforce_helper_certificate_consistency": True,
        "enforce_helper_tx_order_hash": True,
        "enforce_helper_namespace_hash": True,
        "enforce_helper_receipts_root": True,
    }



def test_apply_block_uses_pinned_helper_profile_when_local_runtime_drifts_batch111(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")
    monkeypatch.setenv("WEALL_HELPER_TIMEOUT_MS", "5000")

    leader = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="@leader",
        chain_id="batch111-apply",
        tx_index_path=_tx_index_path(),
    )
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="@follower",
        chain_id="batch111-apply",
        tx_index_path=_tx_index_path(),
    )

    _register_account(leader, "@alice")
    block, _new_state, _applied_ids, _invalid_ids, err = leader.build_block_candidate(max_txs=10)
    assert err == ""
    assert block is not None

    follower.state.setdefault("meta", {})["helper_execution_profile"] = {
        "helper_mode_enabled": True,
        "helper_fast_path_enabled": False,
        "helper_timeout_ms": 5000,
        "enforce_helper_signature": True,
        "enforce_helper_certificate_consistency": True,
        "enforce_helper_tx_order_hash": True,
        "enforce_helper_namespace_hash": True,
        "enforce_helper_receipts_root": True,
    }

    meta = follower.apply_block(block)
    assert meta.ok is True
