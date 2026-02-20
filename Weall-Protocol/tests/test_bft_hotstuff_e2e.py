from __future__ import annotations

from typing import Dict, Any, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import (
    HotStuffBFT,
    BftVote,
    QuorumCert,
    canonical_vote_message,
    quorum_threshold,
    verify_qc,
)


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def test_hotstuff_qc_verification_and_3chain_commit() -> None:
    chain_id = "test"
    validators = ["v1", "v2", "v3", "v4"]  # n=4 => f=1 => thr=3
    thr = quorum_threshold(len(validators))
    assert thr == 3

    # pubkey registry
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    # Minimal ancestry:
    # b1 <- b2 <- b3  (qc on b3 should finalize b1)
    blocks: Dict[str, Any] = {
        "b1": {"prev_block_id": "genesis"},
        "b2": {"prev_block_id": "b1"},
        "b3": {"prev_block_id": "b2"},
    }

    bft = HotStuffBFT(chain_id=chain_id)
    view = 7

    # Build votes for block b3 by 3 validators
    votes: List[dict] = []
    for signer in ["v1", "v2", "v3"]:
        msg = canonical_vote_message(chain_id=chain_id, view=view, block_id="b3", parent_id="b2", signer=signer)
        sig = sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex")
        v = BftVote(chain_id=chain_id, view=view, block_id="b3", parent_id="b2", signer=signer, pubkey=vpub[signer], sig=sig)
        assert v.verify() is True
        votes.append({"signer": signer, "pubkey": vpub[signer], "sig": sig})

    qc = QuorumCert(chain_id=chain_id, view=view, block_id="b3", parent_id="b2", votes=tuple(votes))

    # QC must verify against active set
    assert verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub) is True

    # observing QC should finalize b1 under 3-chain rule: b3->b2->b1
    fin = bft.observe_qc(blocks=blocks, qc=qc)
    assert fin == "b1"
    assert bft.finalized_block_id == "b1"
