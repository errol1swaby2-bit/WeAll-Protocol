from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from weall.runtime.bootstrap_manifest import (
    BootstrapStateReadError,
    build_anchor_from_state,
    read_db_state,
)
from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.testing.prod_fixtures import write_strict_prod_chain_manifest


ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def _executor(tmp_path: Path, name: str, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(TX_INDEX),
    )


def _commit_empty_block(executor: WeAllExecutor, *, ts_ms: int = 1_000) -> dict:
    block, new_state, applied_ids, invalid_ids, err = executor.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=ts_ms,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    meta = executor.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is True, meta.error
    return block


def test_state_root_binds_protocol_meta_but_not_local_runtime_posture() -> None:
    base = {
        "chain_id": "invariant-root",
        "height": 7,
        "accounts": {"@alice": {"nonce": 3}},
        "meta": {
            "protocol_version": "1.5",
            "recent_block_anchor_activation_height": 10,
            "constitutional_clock": {
                "enabled": True,
                "target_block_interval_ms": 20_000,
            },
            "runtime_open": False,
            "observer_mode": False,
            "operator_note": "node-a",
            "runtime_helper_execution_profile": {"helper_mode_enabled": False},
        },
        "groups": {
            "g:1": {
                "members": ["@founder"],
                "meta": {"membership_mode": "approval_required"},
            }
        },
    }

    local_only = copy.deepcopy(base)
    local_only["meta"]["runtime_open"] = True
    local_only["meta"]["observer_mode"] = True
    local_only["meta"]["operator_note"] = "node-b"
    local_only["meta"]["runtime_helper_execution_profile"] = {
        "helper_mode_enabled": True
    }
    assert compute_state_root(local_only) == compute_state_root(base)

    activation_changed = copy.deepcopy(base)
    activation_changed["meta"]["recent_block_anchor_activation_height"] = 1
    assert compute_state_root(activation_changed) != compute_state_root(base)

    clock_changed = copy.deepcopy(base)
    clock_changed["meta"]["constitutional_clock"]["target_block_interval_ms"] = 30_000
    assert compute_state_root(clock_changed) != compute_state_root(base)

    nested_membership_changed = copy.deepcopy(base)
    nested_membership_changed["groups"]["g:1"]["meta"]["membership_mode"] = "open"
    assert compute_state_root(nested_membership_changed) != compute_state_root(base)


def test_equal_root_cannot_hide_recent_anchor_activation_policy() -> None:
    leader = {
        "chain_id": "anchor-policy",
        "height": 0,
        "accounts": {},
        "meta": {"recent_block_anchor_activation_height": 100},
    }
    follower = copy.deepcopy(leader)
    follower["meta"]["recent_block_anchor_activation_height"] = 1

    assert compute_state_root(leader) != compute_state_root(follower)


def test_restart_rejects_snapshot_not_committed_by_tip_block(tmp_path: Path) -> None:
    db_path = tmp_path / "restart-root.db"
    ex = WeAllExecutor(
        db_path=str(db_path),
        node_id="@node",
        chain_id="restart-root",
        tx_index_path=str(TX_INDEX),
    )
    _commit_empty_block(ex)

    with sqlite3.connect(str(db_path)) as con:
        row = con.execute("SELECT state_json FROM ledger_state WHERE id=1").fetchone()
        assert row is not None
        state = json.loads(str(row[0]))
        state.setdefault("params", {})["tampered_after_commit"] = True
        con.execute(
            "UPDATE ledger_state SET state_json=? WHERE id=1",
            (json.dumps(state, sort_keys=True, separators=(",", ":")),),
        )
        con.commit()

    with pytest.raises(ExecutorError, match="snapshot state_root does not match"):
        WeAllExecutor(
            db_path=str(db_path),
            node_id="@node",
            chain_id="restart-root",
            tx_index_path=str(TX_INDEX),
        )


def test_bootstrap_anchor_binds_real_executor_state(tmp_path: Path) -> None:
    ex = _executor(tmp_path, "anchor", chain_id="bootstrap-anchor")
    block = _commit_empty_block(ex)

    anchor = build_anchor_from_state(ex.read_state())
    assert anchor["chain_id"] == "bootstrap-anchor"
    assert anchor["height"] == 1
    assert anchor["tip_hash"] == str(block["block_hash"])
    assert anchor["state_root"] == str(block["header"]["state_root"])

    changed = ex.read_state()
    changed.setdefault("params", {})["anchor_mutation"] = 1
    changed_anchor = build_anchor_from_state(changed)
    assert changed_anchor["state_root"] != anchor["state_root"]
    assert changed_anchor["snapshot_hash"] != anchor["snapshot_hash"]


def test_bootstrap_state_reader_has_fail_closed_mode(tmp_path: Path) -> None:
    db_path = tmp_path / "corrupt.db"
    db_path.write_bytes(b"not a sqlite database")

    with pytest.raises(BootstrapStateReadError):
        read_db_state(db_path, fail_closed=True)


def test_bft_persistence_merges_into_newer_committed_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _executor(tmp_path, "race", chain_id="bft-persist-race")

    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    original_update = ex._ledger_store.update

    def paused_update(fn):
        entered.set()
        assert release.wait(timeout=10)
        return original_update(fn)

    monkeypatch.setattr(ex._ledger_store, "update", paused_update)

    def persist_bft() -> None:
        try:
            ex._bft.view = 7
            ex._bft.last_voted_view = 6
            ex._bft.last_voted_block_id = "b:6"
            ex._persist_bft_state()
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=persist_bft, daemon=True)
    thread.start()
    assert entered.wait(timeout=10)

    block = _commit_empty_block(ex)
    assert int(ex.state.get("height") or 0) == 1

    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert errors == []

    with ex._db.connection() as con:
        row = con.execute(
            "SELECT height, block_id, state_json FROM ledger_state WHERE id=1"
        ).fetchone()
    assert row is not None
    assert int(row["height"] or 0) == 1
    persisted = json.loads(str(row["state_json"]))
    assert int(persisted.get("height") or 0) == 1
    assert str(persisted.get("tip") or "") == str(block["block_id"])
    assert int((persisted.get("bft") or {}).get("last_voted_view") or -1) == 6

    restarted = _executor(tmp_path, "race", chain_id="bft-persist-race")
    assert int(restarted.state.get("height") or 0) == 1
    assert int(restarted._bft.last_voted_view) == 6
    assert restarted._bft.last_voted_block_id == "b:6"


def test_real_executor_bft_state_survives_database_restart(tmp_path: Path) -> None:
    ex = _executor(tmp_path, "bft-restart", chain_id="bft-restart-real")
    ex._bft.view = 11
    ex._bft.last_voted_view = 10
    ex._bft.last_voted_block_id = "b:10"
    ex._persist_bft_state()

    restarted = _executor(tmp_path, "bft-restart", chain_id="bft-restart-real")
    assert restarted._bft.view == 11
    assert restarted._bft.last_voted_view == 10
    assert restarted._bft.last_voted_block_id == "b:10"


def test_validator_bootstrap_verifier_fails_when_production_bootstrap_is_unsafe(
    tmp_path: Path,
) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")
    manifest_path = write_strict_prod_chain_manifest(
        tmp_path / "strict-prod-chain-manifest.json",
        chain_id="weall-prod",
        tx_index_path=tx_index,
    )
    cfg_path = tmp_path / "prod.chain.json"
    cfg_path.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "node_id": "validator-node-1",
                "mode": "prod",
                "db_path": str(tmp_path / "missing.db"),
                "tx_index_path": str(tx_index),
                "chain_manifest_path": str(manifest_path),
                "block_interval_ms": 600_000,
                "max_txs_per_block": 1000,
                "block_reward": 0,
                "api_host": "127.0.0.1",
                "api_port": 8000,
                "allow_unsigned_txs": False,
                "log_level": "INFO",
            }
        ),
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "WEALL_CHAIN_CONFIG_PATH": str(cfg_path),
        "WEALL_CHAIN_MANIFEST_PATH": str(manifest_path),
        "WEALL_REQUIRE_CHAIN_MANIFEST": "1",
        "WEALL_MODE": "prod",
        "WEALL_NET_ENABLED": "1",
        "WEALL_BFT_ENABLED": "1",
        "WEALL_NODE_PUBKEY": "pub",
        "WEALL_NODE_PRIVKEY": "priv",
        "WEALL_VALIDATOR_ACCOUNT": "@validator",
        "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_NET_REQUIRE_PEER_IDENTITY": "1",
        "WEALL_NET_REQUIRE_IDENTITY": "1",
        "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT": "1",
        "WEALL_SYNC_REQUIRE_HEADER_MATCH": "1",
        "WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR": "1",
        "WEALL_BFT_FETCH_ENABLED": "1",
        "WEALL_BFT_FETCH_BASE_URLS": "https://peer-a.example,https://peer-b.example",
        "WEALL_PEER_ID": "validator-node-1",
        "GUNICORN_WORKERS": "1",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
        "WEALL_NET_LOOP_AUTOSTART": "0",
        "WEALL_SIGVERIFY": "0",
    }
    proc = subprocess.run(
        [sys.executable, "scripts/verify_validator_bootstrap.py", "--json"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["bootstrap_report"]["ok"] is False
    assert any(
        "WEALL_SIGVERIFY=0" in str(issue)
        for issue in payload.get("issues", [])
    )


def test_side_channel_ledger_update_cannot_mutate_committed_canonical_state(
    tmp_path: Path,
) -> None:
    ex = _executor(tmp_path, "update-guard", chain_id="update-guard")
    _commit_empty_block(ex)

    def _mutate_canonical(st: dict) -> dict:
        st.setdefault("params", {})["forbidden_side_channel_change"] = True
        return st

    with pytest.raises(RuntimeError, match="ledger_state_update_root_conflict"):
        ex._ledger_store.update(_mutate_canonical)

    # The failed update is atomic and leaves the previously committed root intact.
    persisted = ex._ledger_store.read()
    assert "forbidden_side_channel_change" not in (persisted.get("params") or {})
    assert int(persisted.get("height") or 0) == 1
