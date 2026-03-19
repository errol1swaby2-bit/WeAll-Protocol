from __future__ import annotations

from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

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


def _seed_validator_set(ex: WeAllExecutor, *, validators: list[str], pub: Dict[str, str], epoch: int = 1) -> None:
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


def _make_qc(*, chain_id: str, validators: list[str], vpub: Dict[str, str], vpriv: Dict[str, str], block_id: str, block_hash: str, parent_id: str, view: int, validator_epoch: int, validator_set_hash: str) -> dict:
    votes = []
    for signer in validators[:3]:
        msg = canonical_vote_message(chain_id=chain_id, view=view, block_id=block_id, block_hash=block_hash, parent_id=parent_id, signer=signer, validator_epoch=int(validator_epoch), validator_set_hash=str(validator_set_hash))
        sig = sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex")
        votes.append(BftVote(chain_id=chain_id, view=view, block_id=block_id, block_hash=block_hash, parent_id=parent_id, signer=signer, pubkey=vpub[signer], sig=sig, validator_epoch=int(validator_epoch), validator_set_hash=str(validator_set_hash)).to_json())
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


def _build_committed_block(ex: WeAllExecutor, *, force_ts_ms: int) -> dict:
    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=0, allow_empty=True, force_ts_ms=force_ts_ms)
    assert err == ""
    meta = ex.commit_block_candidate(block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids)
    assert meta.ok is True
    return blk


def test_hash_indexed_pending_qc_can_drive_replay_and_surfaces_in_diagnostics(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    leader = WeAllExecutor(db_path=str(tmp_path / "leader.db"), node_id="v1", chain_id="bft-live", tx_index_path=tx_index_path)
    follower = WeAllExecutor(db_path=str(tmp_path / "follower.db"), node_id="v4", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(leader, validators=validators, pub=vpub, epoch=3)
    _seed_validator_set(follower, validators=validators, pub=vpub, epoch=3)

    block1 = _build_committed_block(leader, force_ts_ms=1000)
    qc1 = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id=str(block1["block_id"]),
        block_hash=str(block1.get("block_hash") or ""),
        parent_id=str(block1.get("prev_block_id") or ""),
        view=1,
        validator_epoch=3,
        validator_set_hash=follower._current_validator_set_hash(),
    )

    block1 = dict(block1)
    block1["validator_epoch"] = 3
    block1["validator_set_hash"] = follower._current_validator_set_hash()

    assert follower.bft_cache_remote_block(block1) is True
    assert int(follower.state.get("height") or 0) == 0

    follower._pending_missing_qcs.clear()
    follower._pending_missing_qcs_by_hash.clear()
    follower._pending_missing_qcs_by_hash[str(block1["block_hash"])] = dict(qc1)

    diag = follower.bft_diagnostics()
    assert diag["pending_missing_qcs"] == [str(block1["block_id"])]
    assert diag["pending_missing_qc_block_hashes"] == [str(block1["block_hash"])]

    metas = follower.bft_try_apply_pending_remote_blocks()
    assert len(metas) == 1
    assert metas[-1].ok is True
    assert int(follower.state.get("height") or 0) == 1
