from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import BftVote, canonical_vote_message, leader_for_view
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _mk_validators(names: Iterable[str]) -> tuple[list[str], dict[str, str], dict[str, str]]:
    validators = [str(x) for x in names]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk
    return validators, vpub, vpriv


def _seed_validator_set(
    ex: WeAllExecutor, *, validators: list[str], pub: dict[str, str], epoch: int = 1
) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
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
    ex.state = st
    ex._ledger_store.write(ex.state)
    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def _make_qc(
    *,
    chain_id: str,
    validators: list[str],
    vpub: dict[str, str],
    vpriv: dict[str, str],
    block_id: str,
    parent_id: str,
    view: int,
    validator_epoch: int,
    validator_set_hash: str,
) -> dict:
    votes = []
    for signer in validators[:3]:
        msg = canonical_vote_message(
            chain_id=chain_id,
            view=view,
            block_id=block_id,
            block_hash=f"{block_id}-h",
            parent_id=parent_id,
            signer=signer,
            validator_epoch=int(validator_epoch),
            validator_set_hash=str(validator_set_hash),
        )
        sig = sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex")
        votes.append(
            BftVote(
                chain_id=chain_id,
                view=view,
                block_id=block_id,
                block_hash=f"{block_id}-h",
                parent_id=parent_id,
                signer=signer,
                pubkey=vpub[signer],
                sig=sig,
                validator_epoch=int(validator_epoch),
                validator_set_hash=str(validator_set_hash),
            ).to_json()
        )
    return {
        "t": "QC",
        "chain_id": chain_id,
        "view": int(view),
        "block_id": block_id,
        "block_hash": f"{block_id}-h",
        "parent_id": parent_id,
        "votes": votes,
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
    }


def _build_committed_block(ex: WeAllExecutor, *, force_ts_ms: int) -> dict:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=force_ts_ms
    )
    assert err == ""
    assert isinstance(blk, dict)
    assert isinstance(st2, dict)
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    assert meta.ok is True
    return blk


@pytest.mark.parametrize("heal_order", [(1, 2, 3), (2, 1, 3)])
def test_partition_heal_replays_missing_chain_without_conflicting_tip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, heal_order: tuple[int, int, int]
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators, vpub, vpriv = _mk_validators(["v1", "v2", "v3", "v4"])

    leader = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="v1",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    follower_a = WeAllExecutor(
        db_path=str(tmp_path / "follower-a.db"),
        node_id="v3",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    follower_b = WeAllExecutor(
        db_path=str(tmp_path / "follower-b.db"),
        node_id="v4",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    for ex in (leader, follower_a, follower_b):
        _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)

    blocks = {
        1: _build_committed_block(leader, force_ts_ms=1000),
        2: _build_committed_block(leader, force_ts_ms=2000),
        3: _build_committed_block(leader, force_ts_ms=3000),
    }
    qcs = {
        i: _make_qc(
            chain_id="bft-live",
            validators=validators,
            vpub=vpub,
            vpriv=vpriv,
            block_id=str(blocks[i]["block_id"]),
            parent_id=str(blocks[i].get("prev_block_id") or ""),
            view=i,
            validator_epoch=3,
            validator_set_hash=follower_a._current_validator_set_hash(),
        )
        for i in (1, 2, 3)
    }
    proposals = {}
    for i in (1, 2, 3):
        blk = dict(blocks[i])
        blk["qc"] = qcs[i]
        blk["validator_epoch"] = 3
        blk["validator_set_hash"] = follower_a._current_validator_set_hash()
        proposals[i] = blk

    # Healthy side receives the full chain in order.
    for i in (1, 2, 3):
        assert (
            follower_a.bft_on_proposal(
                {"view": i, "proposer": leader_for_view(validators, i), "block": proposals[i]}
            )
            is None
        )
    assert int(follower_a.state.get("height") or 0) == 3
    assert str(follower_a.state.get("tip") or "") == str(proposals[3]["block_id"])

    # Partitioned side only sees the tail first and must not move tip prematurely.
    assert (
        follower_b.bft_on_proposal(
            {"view": 3, "proposer": leader_for_view(validators, 3), "block": proposals[3]}
        )
        is None
    )
    assert int(follower_b.state.get("height") or 0) == 0
    assert follower_b.bft_pending_fetch_requests() == [str(proposals[2]["block_id"])]

    # Heal by delivering the missing chain in different orders; convergence must still hold.
    for i in heal_order:
        assert (
            follower_b.bft_on_proposal(
                {"view": i, "proposer": leader_for_view(validators, i), "block": proposals[i]}
            )
            is None
        )

    assert int(follower_b.state.get("height") or 0) == 3
    assert str(follower_b.state.get("tip") or "") == str(proposals[3]["block_id"])
    assert follower_b.bft_pending_fetch_requests() == []
    assert follower_b.state.get("tip_hash") == follower_a.state.get("tip_hash")


def test_out_of_order_qc_buffering_and_stale_replay_do_not_duplicate_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators, vpub, vpriv = _mk_validators(["v1", "v2", "v3", "v4"])

    leader = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="v1",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="v4",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    for ex in (leader, follower):
        _seed_validator_set(ex, validators=validators, pub=vpub, epoch=5)

    block1 = _build_committed_block(leader, force_ts_ms=1000)
    block2 = _build_committed_block(leader, force_ts_ms=2000)
    qc1 = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(block1["block_id"]),
        parent_id=str(block1.get("prev_block_id") or ""),
        view=1,
        validator_epoch=5,
        validator_set_hash=follower._current_validator_set_hash(),
    )
    qc2 = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(block2["block_id"]),
        parent_id=str(block2.get("prev_block_id") or ""),
        view=2,
        validator_epoch=5,
        validator_set_hash=follower._current_validator_set_hash(),
    )

    # Delayed / out-of-order: child QC first, without any blocks.
    assert follower.bft_on_qc(qc2) is None
    assert int(follower.state.get("height") or 0) == 0
    assert follower.bft_pending_fetch_requests() == [str(block2["block_id"])]

    # Child block arrives before parent; it should stay buffered.
    block2j = dict(block2)
    block2j["qc"] = qc2
    block2j["validator_epoch"] = 5
    block2j["validator_set_hash"] = follower._current_validator_set_hash()
    assert (
        follower.bft_on_proposal(
            {"view": 2, "proposer": leader_for_view(validators, 2), "block": block2j}
        )
        is None
    )
    assert int(follower.state.get("height") or 0) == 0

    # Parent QC + parent block arrive later; follower must replay exactly once.
    assert follower.bft_on_qc(qc1) is None
    block1j = dict(block1)
    block1j["qc"] = qc1
    block1j["validator_epoch"] = 5
    block1j["validator_set_hash"] = follower._current_validator_set_hash()
    assert (
        follower.bft_on_proposal(
            {"view": 1, "proposer": leader_for_view(validators, 1), "block": block1j}
        )
        is None
    )
    assert int(follower.state.get("height") or 0) == 2
    first_tip = str(follower.state.get("tip") or "")
    first_tip_hash = str(follower.state.get("tip_hash") or "")

    # Re-delivering the same stale QC/proposal must be idempotent.
    assert follower.bft_on_qc(qc1) is None
    assert (
        follower.bft_on_proposal(
            {"view": 1, "proposer": leader_for_view(validators, 1), "block": block1j}
        )
        is None
    )
    assert int(follower.state.get("height") or 0) == 2
    assert str(follower.state.get("tip") or "") == first_tip
    assert str(follower.state.get("tip_hash") or "") == first_tip_hash


def test_validator_set_transition_rejects_late_old_epoch_messages_after_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    old_validators, old_pub, old_priv = _mk_validators(["v1", "v2", "v3", "v4"])
    new_validators = ["v2", "v3", "v4", "v5"]
    new_pub = dict(old_pub)
    new_priv = dict(old_priv)
    pk5, sk5 = _mk_keypair_hex()
    new_pub["v5"] = pk5
    new_priv["v5"] = sk5

    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="v5",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(follower, validators=new_validators, pub=new_pub, epoch=4)

    old_qc = _make_qc(
        chain_id="bft-live",
        validators=old_validators,
        vpub=old_pub,
        vpriv=old_priv,
        block_id="old-epoch-b1",
        parent_id="genesis",
        view=7,
        validator_epoch=3,
        validator_set_hash="stale-old-set",
    )
    old_block = {
        "block_id": "old-epoch-b1",
        "prev_block_id": "genesis",
        "height": 1,
        "view": 7,
        "proposer": leader_for_view(old_validators, 7),
        "validator_epoch": 3,
        "validator_set_hash": "stale-old-set",
        "header": {
            "chain_id": "bft-live",
            "height": 1,
            "prev_block_hash": "00" * 32,
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "11" * 32,
            "state_root": "22" * 32,
        },
        "txs": [],
        "receipts": [],
        "qc": old_qc,
    }

    assert follower.bft_on_qc(old_qc) is None
    assert (
        follower.bft_on_proposal(
            {"view": 7, "proposer": leader_for_view(old_validators, 7), "block": old_block}
        )
        is None
    )
    assert int(follower.state.get("height") or 0) == 0
    assert follower.bft_pending_fetch_requests() == []

    leader_new = WeAllExecutor(
        db_path=str(tmp_path / "leader-new.db"),
        node_id="v2",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(leader_new, validators=new_validators, pub=new_pub, epoch=4)
    blk = _build_committed_block(leader_new, force_ts_ms=2000)
    qc = _make_qc(
        chain_id="bft-live",
        validators=new_validators,
        vpub=new_pub,
        vpriv=new_priv,
        block_id=str(blk["block_id"]),
        parent_id=str(blk.get("prev_block_id") or ""),
        view=8,
        validator_epoch=4,
        validator_set_hash=follower._current_validator_set_hash(),
    )
    blkj = dict(blk)
    blkj["qc"] = qc
    blkj["validator_epoch"] = 4
    blkj["validator_set_hash"] = follower._current_validator_set_hash()
    assert (
        follower.bft_on_proposal(
            {"view": 8, "proposer": leader_for_view(new_validators, 8), "block": blkj}
        )
        is None
    )
    assert int(follower.state.get("height") or 0) == 1
    assert str(follower.state.get("tip") or "") == str(blkj["block_id"])

    # A stale old-epoch QC replay after activation must not regress or enqueue fetches.
    assert follower.bft_on_qc(old_qc) is None
    assert int(follower.state.get("height") or 0) == 1
    assert str(follower.state.get("tip") or "") == str(blkj["block_id"])
    assert follower.bft_pending_fetch_requests() == []


def test_crash_mid_commit_preserves_vote_safety_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators, vpub, vpriv = _mk_validators(["v1", "v2", "v3", "v4"])

    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v2"])

    db_path = str(tmp_path / "node.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="v2", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)
    ex._validate_remote_proposal_for_vote = lambda block: True

    leader = leader_for_view(validators, 1)
    assert leader == "v2"
    proposal = {
        "view": 1,
        "proposer": leader,
        "block": {
            "block_id": "vote-safe-b1",
            "prev_block_id": "",
            "height": 1,
            "view": 1,
            "proposer": leader,
        },
    }
    vote = ex.bft_on_proposal(proposal)
    assert isinstance(vote, dict)
    assert ex.state.get("bft", {}).get("last_voted_view") == 1
    assert ex.state.get("bft", {}).get("last_voted_block_id") == "vote-safe-b1"

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user0",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
    assert err == ""

    monkeypatch.setenv("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "1")
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    assert meta.ok is False
    monkeypatch.delenv("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", raising=False)

    ex2 = WeAllExecutor(
        db_path=db_path, node_id="v2", chain_id="bft-live", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex2, validators=validators, pub=vpub, epoch=3)
    st = ex2.read_state()
    assert int(st.get("height") or 0) == 0
    assert len(ex2.read_mempool()) == 1
    assert ex2.state.get("bft", {}).get("last_voted_view") == 1
    assert ex2.state.get("bft", {}).get("last_voted_block_id") == "vote-safe-b1"

    conflicting = {
        "view": 1,
        "proposer": leader,
        "block": {
            "block_id": "vote-safe-b2",
            "prev_block_id": "",
            "height": 1,
            "view": 1,
            "proposer": leader,
        },
    }
    assert ex2.bft_on_proposal(conflicting) is None


def test_epoch_transition_prunes_stale_pending_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    old_validators, old_pub, old_priv = _mk_validators(["v1", "v2", "v3", "v4"])
    new_validators = ["v2", "v3", "v4", "v5"]
    new_pub = dict(old_pub)
    new_priv = dict(old_priv)
    pk5, sk5 = _mk_keypair_hex()
    new_pub["v5"] = pk5
    new_priv["v5"] = sk5

    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower-prune.db"),
        node_id="v5",
        chain_id="bft-live",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(follower, validators=new_validators, pub=new_pub, epoch=4)

    stale_qc = _make_qc(
        chain_id="bft-live",
        validators=old_validators,
        vpub=old_pub,
        vpriv=old_priv,
        block_id="old-epoch-buffered",
        parent_id="genesis",
        view=4,
        validator_epoch=3,
        validator_set_hash="stale-old-set",
    )
    stale_block = {
        "block_id": "old-epoch-buffered",
        "prev_block_id": "genesis",
        "height": 1,
        "view": 4,
        "proposer": leader_for_view(old_validators, 4),
        "validator_epoch": 3,
        "validator_set_hash": "stale-old-set",
        "header": {
            "chain_id": "bft-live",
            "height": 1,
            "prev_block_hash": "00" * 32,
            "block_ts_ms": 1000,
            "tx_ids": [],
            "receipts_root": "11" * 32,
            "state_root": "22" * 32,
        },
        "txs": [],
        "receipts": [],
    }

    follower._pending_missing_qcs["old-epoch-buffered"] = stale_qc
    follower._pending_remote_blocks["old-epoch-buffered"] = stale_block

    # Diagnostics should scrub stale artifacts after the epoch transition.
    diag = follower.bft_diagnostics()
    assert diag["pending_artifacts_pruned"] is True
    assert diag["pending_remote_blocks_count"] == 0
    assert diag["pending_missing_qcs_count"] == 0
    assert follower.bft_pending_fetch_requests() == []
