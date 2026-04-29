from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _bootstrap_account(ex: WeAllExecutor, *, account_id: str) -> None:
    st = dict(ex.state)
    accounts = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}
    accounts[account_id] = {
        "pubkeys": [f"k:{account_id}"],
        "nonce": 1,
        "poh_tier": 3,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 0,
        "session_keys": {},
    }
    st["accounts"] = accounts
    consensus = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    consensus["validator_set"] = {
        "epoch": 7,
        "active_set": ["@leader", "@helper-a", "@helper-b"],
    }
    st["consensus"] = consensus
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]
    ex.state = ex._store.read()  # type: ignore[attr-defined]


def test_bootstrap_dev_preserves_requested_helper_profile_batch123(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_profile.db"),
        node_id="@node",
        chain_id="batch123-helper-profile",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )

    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["requested_state"] == "bootstrap_registration"
    assert lifecycle["effective_state"] == "bootstrap_registration"

    meta = ex.read_state().get("meta", {})
    helper_profile = meta.get("helper_execution_profile") if isinstance(meta.get("helper_execution_profile"), dict) else {}
    assert helper_profile.get("helper_mode_enabled") is True
    assert helper_profile.get("helper_fast_path_enabled") is True


def test_bootstrap_dev_keeps_helper_metadata_available_batch123(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "helper_exec.db"),
        node_id="@leader",
        chain_id="batch123-helper-exec",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    _bootstrap_account(ex, account_id="@alice")

    ok = ex.submit_tx(
        {
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "@alice",
            "nonce": 2,
            "payload": {
                "body": "hello bootstrap helper",
                "visibility": "public",
                "tags": ["batch123"],
                "media": [],
            },
        }
    )
    assert ok["ok"] is True

    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1)
    assert err == ""
    assert block is not None
    assert new_state is not None
    assert applied_ids
    assert invalid_ids == []
    assert isinstance(block.get("helper_execution"), dict)
    marker = new_state.get("meta", {}).get("helper_execution_last")
    assert isinstance(marker, dict)
    assert marker.get("height") == block.get("height")
