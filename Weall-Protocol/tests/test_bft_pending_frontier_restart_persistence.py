from __future__ import annotations

import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import BftVote, canonical_vote_message
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


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
    block_hash: str,
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
            block_hash=block_hash,
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
                block_hash=block_hash,
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
        "block_hash": block_hash,
        "parent_id": parent_id,
        "votes": votes,
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
    }


def _backup_sqlite(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(src)) as src_con, sqlite3.connect(str(dst)) as dst_con:
        src_con.backup(dst_con)


def _build_committed_block(ex: WeAllExecutor, *, force_ts_ms: int) -> dict:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=force_ts_ms
    )
    assert err == ""
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    assert meta.ok is True
    return blk


def test_pending_remote_frontier_survives_restart_and_replays(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    source_db = tmp_path / "source.db"
    dest_db = tmp_path / "dest.db"
    source = WeAllExecutor(
        db_path=str(source_db), node_id="v1", chain_id="bft-restart", tx_index_path=tx_index_path
    )
    _seed_validator_set(source, validators=validators, pub=vpub, epoch=3)

    _build_committed_block(source, force_ts_ms=1000)
    _backup_sqlite(source_db, dest_db)
    _backup_sqlite(source_db.with_name("source.aux.sqlite"), dest_db.with_name("dest.aux.sqlite"))

    dest = WeAllExecutor(
        db_path=str(dest_db), node_id="v4", chain_id="bft-restart", tx_index_path=tx_index_path
    )

    block2 = _build_committed_block(source, force_ts_ms=2000)
    block3 = _build_committed_block(source, force_ts_ms=3000)
    set_hash = dest._current_validator_set_hash()
    qc2 = _make_qc(
        chain_id="bft-restart",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(block2["block_id"]),
        block_hash=str(block2["block_hash"]),
        parent_id=str(block2["prev_block_id"]),
        view=2,
        validator_epoch=3,
        validator_set_hash=set_hash,
    )
    qc3 = _make_qc(
        chain_id="bft-restart",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(block3["block_id"]),
        block_hash=str(block3["block_hash"]),
        parent_id=str(block3["prev_block_id"]),
        view=3,
        validator_epoch=3,
        validator_set_hash=set_hash,
    )

    pending_block3 = dict(block3)
    pending_block3["qc"] = qc3
    pending_block3["validator_epoch"] = 3
    pending_block3["validator_set_hash"] = set_hash

    assert dest.bft_cache_remote_block(pending_block3) is True
    before = dest.bft_diagnostics()
    assert str(block3["block_id"]) in list(before.get("pending_remote_blocks") or [])
    assert str(block3["block_id"]) in list(before.get("pending_missing_qcs") or [])
    assert int(dest.state.get("height") or 0) == 1

    restarted = WeAllExecutor(
        db_path=str(tmp_path / "dest.db"),
        node_id="v4",
        chain_id="bft-restart",
        tx_index_path=tx_index_path,
    )
    after_restart = restarted.bft_diagnostics()
    assert str(block3["block_id"]) in list(after_restart.get("pending_remote_blocks") or [])
    assert str(block3["block_id"]) in list(after_restart.get("pending_missing_qcs") or [])

    pending_block2 = dict(block2)
    pending_block2["qc"] = qc2
    pending_block2["validator_epoch"] = 3
    pending_block2["validator_set_hash"] = set_hash
    assert restarted.bft_cache_remote_block(pending_block2) is True
    assert int(restarted.state.get("height") or 0) == 3
    assert str(restarted.state.get("tip") or "") == str(block3["block_id"])

    final_diag = restarted.bft_diagnostics()
    assert int(final_diag.get("pending_remote_blocks_count") or 0) == 0
    assert int(final_diag.get("pending_missing_qcs_count") or 0) == 0


def test_pending_candidate_survives_restart(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v1"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v1"])

    db_path = str(tmp_path / "candidate.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="v1", chain_id="bft-candidate-restart", tx_index_path=tx_index_path
    )
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=5)
    ex.bft_set_view(0)

    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    block_id = str(proposal["block_id"])

    before = ex.bft_diagnostics()
    assert block_id in list(before.get("pending_candidates") or [])

    ex2 = WeAllExecutor(
        db_path=db_path, node_id="v1", chain_id="bft-candidate-restart", tx_index_path=tx_index_path
    )
    after = ex2.bft_diagnostics()
    assert block_id in list(after.get("pending_candidates") or [])
    restored = ex2._bft_pending_block_json(block_id)
    assert isinstance(restored, dict)
    assert str(restored.get("block_id") or "") == block_id
