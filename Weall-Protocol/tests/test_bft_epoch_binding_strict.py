from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import BftTimeout, QuorumCert, canonical_timeout_message, canonical_vote_message, verify_qc


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _keys():
    out = {}
    for signer in ["@v1", "@v2", "@v3", "@v4"]:
        out[signer] = _mk_keypair_hex()
    return out


def _validators():
    return ["@v1", "@v2", "@v3", "@v4"]


def test_qc_rejects_legacy_votes_when_epoch_metadata_present() -> None:
    keys = _keys()
    votes = []
    for signer in ["@v1", "@v2", "@v3"]:
        pub, priv = keys[signer]
        msg = canonical_vote_message(chain_id="chain-A", view=7, block_id="b7", block_hash="bh7", parent_id="b6", signer=signer)
        sig = sign_ed25519(message=msg, privkey=priv, encoding="hex")
        votes.append(
            {
                "t": "VOTE",
                "chain_id": "chain-A",
                "view": 7,
                "block_id": "b7",
                "parent_id": "b6",
                "signer": signer,
                "pubkey": pub,
                "sig": sig,
            }
        )

    qc = QuorumCert(
        chain_id="chain-A",
        view=7,
        block_id="b7",
        block_hash="bh7",
        parent_id="b6",
        votes=tuple(votes),
        validator_epoch=5,
        validator_set_hash="sethash",
    )
    assert verify_qc(qc=qc, validators=_validators(), vpub={k: v[0] for k, v in keys.items()}) is False


def test_timeout_json_carries_epoch_binding() -> None:
    pub, priv = _mk_keypair_hex()
    msg = canonical_timeout_message(
        chain_id="chain-A",
        view=9,
        high_qc_id="b8",
        signer="@v1",
        validator_epoch=5,
        validator_set_hash="sethash",
    )
    sig = sign_ed25519(message=msg, privkey=priv, encoding="hex")
    tmo = BftTimeout(
        chain_id="chain-A",
        view=9,
        high_qc_id="b8",
        signer="@v1",
        pubkey=pub,
        sig=sig,
        validator_epoch=5,
        validator_set_hash="sethash",
    )
    tj = tmo.to_json()
    assert tj["validator_epoch"] == 5
    assert tj["validator_set_hash"] == "sethash"
