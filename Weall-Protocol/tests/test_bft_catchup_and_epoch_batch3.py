from __future__ import annotations

from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from weall.runtime.bft_hotstuff import BftVote, canonical_vote_message
from weall.runtime.executor import WeAllExecutor
from weall.crypto.sig import sign_ed25519


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
    set_hash = ex._current_validator_set_hash()
    st["consensus"]["validator_set"]["set_hash"] = set_hash
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
    ex.state = st
    ex._ledger_store.write(ex.state)
    # recompute hash after state update so helper sees registry+active set.
    st = ex.read_state()
    st["consensus"]["validator_set"]["set_hash"] = ex._current_validator_set_hash()
    ex.state = st
    ex._ledger_store.write(ex.state)


def _make_qc(
    *,
    chain_id: str,
    validators: list[str],
    vpub: Dict[str, str],
    vpriv: Dict[str, str],
    block_id: str,
    parent_id: str,
    view: int,
    validator_epoch: int | None = None,
    validator_set_hash: str | None = None,
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
    out = {
        "t": "QC",
        "chain_id": chain_id,
        "view": int(view),
        "block_id": block_id,
        "block_hash": f"{block_id}-h",
        "parent_id": parent_id,
        "votes": votes,
    }
    if validator_epoch is not None:
        out["validator_epoch"] = int(validator_epoch)
    if validator_set_hash is not None:
        out["validator_set_hash"] = str(validator_set_hash)
    return out


def test_bft_on_qc_tracks_missing_block_fetch_request(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    ex = WeAllExecutor(db_path=str(tmp_path / "node.db"), node_id="@v1", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)
    qcj = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id="missing-block-1",
        parent_id="genesis",
        view=7,
        validator_epoch=3,
        validator_set_hash=ex._current_validator_set_hash(),
    )

    assert ex.bft_on_qc(qcj) is None
    assert ex.bft_pending_fetch_requests() == ["missing-block-1"]


def test_bft_verify_qc_rejects_stale_epoch_metadata(tmp_path: Path) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    ex = WeAllExecutor(db_path=str(tmp_path / "node.db"), node_id="@v1", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=2)
    qcj = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id="b-epoch",
        parent_id="genesis",
        view=4,
        validator_epoch=1,
        validator_set_hash=ex._current_validator_set_hash(),
    )

    assert ex.bft_verify_qc_json(qcj) is None


def test_bft_on_proposal_rejects_validator_set_hash_mismatch(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    ex = WeAllExecutor(db_path=str(tmp_path / "node.db"), node_id="@v2", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=5)
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v2"])

    qcj = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id="proposal-1",
        parent_id="genesis",
        view=5,
        validator_epoch=5,
        validator_set_hash=ex._current_validator_set_hash(),
    )
    proposal = {
        "block": {
            "block_id": "proposal-1",
            "prev_block_id": "genesis",
            "height": 1,
            "validator_epoch": 5,
            "validator_set_hash": "deadbeef",
            "qc": qcj,
        },
        "view": 5,
        "proposer": "v1",
    }

    assert ex.bft_on_proposal(proposal) is None
    assert "proposal-1" not in ex.bft_pending_fetch_requests()
