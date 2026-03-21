from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _wait_for_marker(marker: Path, timeout_s: float = 8.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline and not marker.exists():
        time.sleep(0.02)
    assert marker.exists(), "child did not reach post-insert window"


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(
    ex: WeAllExecutor, *, validators: list[str], pub: dict[str, str], epoch: int = 1
) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("validators", {})
    st["validators"].setdefault("registry", {})
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    st["consensus"].setdefault("validator_set", {})
    st["consensus"]["validator_set"]["active_set"] = list(validators)
    st["consensus"]["validator_set"]["epoch"] = int(epoch)
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
        st["validators"]["registry"].setdefault(v, {})
        st["validators"]["registry"][v]["pubkey"] = pub[v]
    ex.state = st
    ex._ledger_store.write(ex.state)
    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def _leader_views_for_v2(count: int) -> list[int]:
    # With validators ["@v1", "@v2", "@v3", "@v4"], @v2 leads views 1, 5, 9, ...
    return [1 + (4 * i) for i in range(count)]


def test_repeated_atomic_commit_crash_cycles_preserve_height_zero_until_clean_commit(
    tmp_path: Path,
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    child_code = r"""
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ["DB_PATH"],
    node_id="@alice",
    chain_id="batch40-crash-cycles",
    tx_index_path=os.environ["TX_INDEX"],
)

signer = os.environ["SIGNER"]
sub = ex.submit_tx(
    {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": {"pubkey": f"k:{signer}"},
    }
)
assert sub.get("ok") is True

blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
assert err == ""

meta = ex.commit_block_candidate(
    block=blk,
    new_state=st2,
    applied_ids=applied_ids,
    invalid_ids=invalid_ids,
)
assert meta.ok is True
"""

    for i in range(4):
        marker = Path(tmp_path / f"child_ready_{i}.marker")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["DB_PATH"] = db_path
        env["TX_INDEX"] = tx_index_path
        env["SIGNER"] = f"@user{i}"
        env["WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS"] = "5000"
        env["WEALL_TEST_MARKER_PATH"] = str(marker)

        p = subprocess.Popen([sys.executable, "-c", child_code], env=env)
        _wait_for_marker(marker)
        p.kill()
        p.wait(timeout=5)

        ex = WeAllExecutor(
            db_path=db_path,
            node_id="@alice",
            chain_id="batch40-crash-cycles",
            tx_index_path=tx_index_path,
        )
        st = ex.read_state()
        assert int(st.get("height", 0)) == 0

        mp = ex.read_mempool()
        assert len(mp) == i + 1

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="batch40-crash-cycles",
        tx_index_path=tx_index_path,
    )

    committed_block_ids: list[str] = []
    for _ in range(10):
        mp = ex2.read_mempool()
        if not mp:
            break
        meta = ex2.produce_block(max_txs=1)
        assert meta.ok is True
        latest = ex2.get_latest_block()
        committed_block_ids.append(str(latest.get("block_id") or ""))

    assert len(ex2.read_mempool()) == 0
    st2 = ex2.read_state()
    assert int(st2.get("height", 0)) == 4
    assert len(committed_block_ids) == 4
    assert len(set(committed_block_ids)) == 4

    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="batch40-crash-cycles",
        tx_index_path=tx_index_path,
    )
    st3 = ex3.read_state()
    assert int(st3.get("height", 0)) == 4
    latest3 = ex3.get_latest_block()
    assert str(latest3.get("block_id") or "") == committed_block_ids[-1]


def test_repeated_vote_restart_cycles_never_regress_last_voted_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["@v1", "@v2", "@v3", "@v4"]
    pub: dict[str, str] = {}
    priv: dict[str, str] = {}
    for v in validators:
        pub[v], priv[v] = _mk_keypair_hex()

    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub["@v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", priv["@v2"])

    db_path = str(tmp_path / "node.db")

    last_view = 0
    voted_block_ids: list[str] = []

    for view in _leader_views_for_v2(5):
        ex = WeAllExecutor(
            db_path=db_path, node_id="@v2", chain_id="batch40-votes", tx_index_path=tx_index_path
        )
        _seed_validator_set(ex, validators=validators, pub=pub)

        ex.bft_set_view(view)
        proposal = ex.bft_leader_propose(max_txs=0)
        assert isinstance(proposal, dict)

        vote = ex.bft_on_proposal(proposal)
        assert isinstance(vote, dict)

        current_view = int(ex.state.get("bft", {}).get("last_voted_view") or 0)
        current_block_id = str(ex.state.get("bft", {}).get("last_voted_block_id") or "")
        assert current_view == view
        assert current_view >= last_view
        assert current_block_id == str(proposal.get("block_id") or "")
        voted_block_ids.append(current_block_id)

        ex2 = WeAllExecutor(
            db_path=db_path, node_id="@v2", chain_id="batch40-votes", tx_index_path=tx_index_path
        )
        _seed_validator_set(ex2, validators=validators, pub=pub)

        restarted_view = int(ex2.state.get("bft", {}).get("last_voted_view") or 0)
        restarted_block_id = str(ex2.state.get("bft", {}).get("last_voted_block_id") or "")
        assert restarted_view == view
        assert restarted_view >= last_view
        assert restarted_block_id == current_block_id

        replayed = ex2.bft_on_proposal(proposal)
        assert isinstance(replayed, dict)
        assert str(replayed.get("block_id") or "") == str(proposal.get("block_id") or "")

        ex3 = WeAllExecutor(
            db_path=db_path, node_id="@v2", chain_id="batch40-votes", tx_index_path=tx_index_path
        )
        _seed_validator_set(ex3, validators=validators, pub=pub)
        assert int(ex3.state.get("bft", {}).get("last_voted_view") or 0) == view
        assert str(ex3.state.get("bft", {}).get("last_voted_block_id") or "") == current_block_id

        last_view = view

    assert last_view == 17
    assert len(voted_block_ids) == 5
    assert all(voted_block_ids)


def test_repeated_restart_cycles_do_not_double_finalize_blocks(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="batch40-restart", tx_index_path=tx_index_path
    )

    block_ids_seen: list[str] = []
    heights_seen: list[int] = []

    for i in range(5):
        sub = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": f"@user{i}",
                "nonce": 1,
                "payload": {"pubkey": f"k:{i}"},
            }
        )
        assert sub["ok"] is True
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True

        latest = ex.get_latest_block()
        block_id = str(latest.get("block_id") or "")
        height = int(latest.get("header", {}).get("height") or 0)
        block_ids_seen.append(block_id)
        heights_seen.append(height)

        ex = WeAllExecutor(
            db_path=db_path,
            node_id="@alice",
            chain_id="batch40-restart",
            tx_index_path=tx_index_path,
        )
        st = ex.read_state()
        assert int(st.get("height", 0)) == i + 1
        latest_after_restart = ex.get_latest_block()
        assert str(latest_after_restart.get("block_id") or "") == block_id

    assert heights_seen == [1, 2, 3, 4, 5]
    assert len(set(block_ids_seen)) == 5

    ex_final = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="batch40-restart", tx_index_path=tx_index_path
    )
    st_final = ex_final.read_state()
    assert int(st_final.get("height", 0)) == 5
    latest_final = ex_final.get_latest_block()
    assert str(latest_final.get("block_id") or "") == block_ids_seen[-1]


def test_mixed_commit_crash_and_vote_restart_sequence_preserves_single_canonical_tip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    # Part A: repeated commit crashes, then clean finalize.
    db_exec = str(tmp_path / "exec.db")

    child_code = r"""
import os
from weall.runtime.executor import WeAllExecutor

ex = WeAllExecutor(
    db_path=os.environ["DB_PATH"],
    node_id="@alice",
    chain_id="batch40-mixed",
    tx_index_path=os.environ["TX_INDEX"],
)

signer = os.environ["SIGNER"]
sub = ex.submit_tx(
    {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "payload": {"pubkey": f"k:{signer}"},
    }
)
assert sub.get("ok") is True

blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
assert err == ""

meta = ex.commit_block_candidate(
    block=blk,
    new_state=st2,
    applied_ids=applied_ids,
    invalid_ids=invalid_ids,
)
assert meta.ok is True
"""

    for i in range(2):
        marker = Path(tmp_path / f"mixed_ready_{i}.marker")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["DB_PATH"] = db_exec
        env["TX_INDEX"] = tx_index_path
        env["SIGNER"] = f"@mix{i}"
        env["WEALL_TEST_SLEEP_AFTER_BLOCK_INSERT_MS"] = "5000"
        env["WEALL_TEST_MARKER_PATH"] = str(marker)

        p = subprocess.Popen([sys.executable, "-c", child_code], env=env)
        _wait_for_marker(marker)
        p.kill()
        p.wait(timeout=5)

    ex = WeAllExecutor(
        db_path=db_exec, node_id="@alice", chain_id="batch40-mixed", tx_index_path=tx_index_path
    )
    assert int(ex.read_state().get("height", 0)) == 0
    assert len(ex.read_mempool()) == 2

    while ex.read_mempool():
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True

    latest_before_restart = ex.get_latest_block()
    assert isinstance(latest_before_restart, dict)
    tip_before_restart = str(latest_before_restart.get("block_id") or "")
    assert tip_before_restart

    ex_restart = WeAllExecutor(
        db_path=db_exec, node_id="@alice", chain_id="batch40-mixed", tx_index_path=tx_index_path
    )
    latest_after_restart = ex_restart.get_latest_block()
    assert str(latest_after_restart.get("block_id") or "") == tip_before_restart

    # Part B: repeated vote-state restarts on a separate DB, ensuring monotonic vote persistence.
    db_vote = str(tmp_path / "vote.db")
    validators = ["@v1", "@v2", "@v3", "@v4"]
    pub: dict[str, str] = {}
    priv: dict[str, str] = {}
    for v in validators:
        pub[v], priv[v] = _mk_keypair_hex()

    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pub["@v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", priv["@v2"])

    last_view = 0
    for view in _leader_views_for_v2(3):
        ex_vote = WeAllExecutor(
            db_path=db_vote, node_id="@v2", chain_id="batch40-vote-mixed", tx_index_path=tx_index_path
        )
        _seed_validator_set(ex_vote, validators=validators, pub=pub)
        ex_vote.bft_set_view(view)
        proposal = ex_vote.bft_leader_propose(max_txs=0)
        assert isinstance(proposal, dict)
        vote = ex_vote.bft_on_proposal(proposal)
        assert isinstance(vote, dict)
        assert int(ex_vote.state.get("bft", {}).get("last_voted_view") or 0) == view
        assert view >= last_view

        ex_vote_restart = WeAllExecutor(
            db_path=db_vote, node_id="@v2", chain_id="batch40-vote-mixed", tx_index_path=tx_index_path
        )
        _seed_validator_set(ex_vote_restart, validators=validators, pub=pub)
        assert int(ex_vote_restart.state.get("bft", {}).get("last_voted_view") or 0) == view
        last_view = view

    # Final restart on execution DB still yields the same canonical tip.
    ex_final = WeAllExecutor(
        db_path=db_exec, node_id="@alice", chain_id="batch40-mixed", tx_index_path=tx_index_path
    )
    latest_final = ex_final.get_latest_block()
    assert str(latest_final.get("block_id") or "") == tip_before_restart
    assert int(ex_final.read_state().get("height", 0)) == 2

