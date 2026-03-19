from __future__ import annotations

import os
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import TimeoutCertificate, canonical_timeout_message, canonical_vote_message, quorum_threshold
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(ex: WeAllExecutor, *, validators: list[str], pub: Dict[str, str], epoch: int = 3) -> None:
    st = ex.read_state()
    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"]["active_set"] = list(validators)
    st.setdefault("consensus", {})
    st["consensus"].setdefault("validators", {})
    st["consensus"]["validators"].setdefault("registry", {})
    for v in validators:
        st["consensus"]["validators"]["registry"].setdefault(v, {})
        st["consensus"]["validators"]["registry"][v]["pubkey"] = pub[v]
    st["consensus"].setdefault("epochs", {})
    st["consensus"]["epochs"]["current"] = int(epoch)
    from weall.runtime.bft_hotstuff import normalize_validators, validator_set_hash
    vals = normalize_validators(list(validators))
    st["consensus"]["validator_set"] = {
        "epoch": int(epoch),
        "validators": list(vals),
        "set_hash": validator_set_hash(vals),
    }
    ex.state = st
    ex._ledger_store.write(ex.state)


def _signed_timeout(*, chain_id: str, signer: str, view: int, high_qc_id: str, validator_epoch: int, validator_set_hash: str, pubkey: str, privkey: str) -> dict:
    msg = canonical_timeout_message(
        chain_id=chain_id,
        view=view,
        high_qc_id=high_qc_id,
        signer=signer,
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash,
    )
    return {
        "t": "TIMEOUT",
        "chain_id": chain_id,
        "view": int(view),
        "high_qc_id": high_qc_id,
        "signer": signer,
        "pubkey": pubkey,
        "sig": sign_ed25519(message=msg, privkey=privkey, encoding="hex"),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": validator_set_hash,
    }


def _make_qc(*, chain_id: str, validators: list[str], vpub: Dict[str, str], vpriv: Dict[str, str], block_id: str, block_hash: str, parent_id: str, view: int, validator_epoch: int, validator_set_hash: str) -> dict:
    votes = []
    needed = quorum_threshold(len(validators))
    for signer in validators[:needed]:
        msg = canonical_vote_message(
            chain_id=chain_id,
            view=view,
            block_id=block_id,
            block_hash=block_hash,
            parent_id=parent_id,
            signer=signer,
            validator_epoch=validator_epoch,
            validator_set_hash=validator_set_hash,
        )
        votes.append({
            "t": "VOTE",
            "chain_id": chain_id,
            "view": int(view),
            "block_id": block_id,
            "block_hash": block_hash,
            "parent_id": parent_id,
            "signer": signer,
            "pubkey": vpub[signer],
            "sig": sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex"),
            "validator_epoch": int(validator_epoch),
            "validator_set_hash": validator_set_hash,
        })
    return {
        "t": "QC",
        "chain_id": chain_id,
        "view": int(view),
        "block_id": block_id,
        "block_hash": block_hash,
        "parent_id": parent_id,
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": validator_set_hash,
        "votes": votes,
    }


def test_timeout_certificate_persists_across_restart(tmp_path: Path) -> None:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    validators = ["v1", "v2", "v3", "v4"]
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    db_path = str(tmp_path / "node.db")
    ex = WeAllExecutor(db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)
    set_hash = ex._current_validator_set_hash()

    for signer in ["v1", "v2", "v3"]:
        ex.bft_handle_timeout(
            _signed_timeout(
                chain_id="bft-live",
                signer=signer,
                view=0,
                high_qc_id="qc-block-7",
                validator_epoch=3,
                validator_set_hash=set_hash,
                pubkey=vpub[signer],
                privkey=vpriv[signer],
            )
        )

    tc = ex._bft.best_timeout_certificate()
    assert tc is not None
    assert tc.view == 0
    assert tc.high_qc_id == "qc-block-7"
    assert list(tc.signers) == ["v1", "v2", "v3"]

    ex2 = WeAllExecutor(db_path=db_path, node_id="@v4", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(ex2, validators=validators, pub=vpub, epoch=3)
    tc2 = ex2._bft.best_timeout_certificate()
    assert tc2 is not None
    assert tc2.high_qc_id == "qc-block-7"
    assert list(tc2.signers) == ["v1", "v2", "v3"]


def test_leader_proposal_can_use_cached_qc_from_timeout_certificate(tmp_path: Path, monkeypatch) -> None:
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

    ex = WeAllExecutor(db_path=str(tmp_path / "leader.db"), node_id="@v2", chain_id="bft-live", tx_index_path=tx_index_path)
    _seed_validator_set(ex, validators=validators, pub=vpub, epoch=3)

    set_hash = ex._current_validator_set_hash()
    qc = _make_qc(
        chain_id="bft-live",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id="known-qc-block",
        block_hash="11" * 32,
        parent_id="genesis",
        view=0,
        validator_epoch=3,
        validator_set_hash=set_hash,
    )
    ex._pending_missing_qcs["known-qc-block"] = qc
    ex._bft.last_timeout_certificate = TimeoutCertificate(
        chain_id="bft-live",
        view=0,
        high_qc_id="known-qc-block",
        signer_count=3,
        signers=("v1", "v3", "v4"),
        validator_epoch=3,
        validator_set_hash=set_hash,
    )
    ex._bft.high_qc = None
    ex._bft.view = 1  # deterministic leader is v2 for sorted [v1,v2,v3,v4]

    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", vpub["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", vpriv["v2"])

    proposal = ex.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)
    assert isinstance(proposal.get("justify_qc"), dict)
    assert proposal["justify_qc"]["block_id"] == "known-qc-block"
