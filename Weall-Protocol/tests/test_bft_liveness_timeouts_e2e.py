# tests/test_bft_liveness_timeouts_e2e.py
from __future__ import annotations

from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import BftTimeout, canonical_timeout_message
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _mk_keypair_hex() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk_b.hex(), sk_b.hex()


def _seed_validator_set(ex: WeAllExecutor, *, validators: list[str], pub: Dict[str, str]) -> None:
    # Executor expects:
    # - roles.validators.active_set for membership
    # - consensus.validators.registry[acct].pubkey for signature verify
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

    # Persist the modified state.
    ex.state = st
    ex._ledger_store.write(ex.state)


def test_bft_liveness_advances_view_via_timeouts_threshold(tmp_path: Path) -> None:
    """E2E-ish liveness: if the leader is silent and enough validators TIMEOUT,
    the HotStuff view must advance deterministically on every node.

    This test intentionally bypasses the network stack and directly routes
    signed TIMEOUT messages to each node's executor consensus engine.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    # n=4 => f=1 => threshold=3
    validators = ["v1", "v2", "v3", "v4"]
    vpub: Dict[str, str] = {}
    vpriv: Dict[str, str] = {}
    for v in validators:
        pk, sk = _mk_keypair_hex()
        vpub[v] = pk
        vpriv[v] = sk

    # Four independent nodes sharing the same validator set.
    ex: Dict[str, WeAllExecutor] = {}
    for i, vid in enumerate(validators):
        db_path = str(tmp_path / f"node_{i}.db")
        ex[vid] = WeAllExecutor(db_path=db_path, node_id=f"@{vid}", chain_id="bft-live", tx_index_path=tx_index_path)
        _seed_validator_set(ex[vid], validators=validators, pub=vpub)

    # All nodes start at view=0.
    for vid in validators:
        assert ex[vid].bft_current_view() == 0

    # Leader is assumed silent; 3 of 4 validators emit TIMEOUT for view=0.
    view = 0
    high_qc_id = "genesis"  # no QC yet

    timeouts: list[dict] = []
    for signer in ["v1", "v2", "v3"]:
        msg = canonical_timeout_message(chain_id="bft-live", view=view, high_qc_id=high_qc_id, signer=signer)
        sig = sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex")
        tmo = BftTimeout(
            chain_id="bft-live",
            view=view,
            high_qc_id=high_qc_id,
            signer=signer,
            pubkey=vpub[signer],
            sig=sig,
        )
        assert tmo.verify() is True
        timeouts.append(tmo.to_json())

    # Deliver the timeouts to all nodes in shuffled-ish order.
    # Each node should independently advance to view=1 once it observes threshold.
    for vid in validators:
        for tmoj in [timeouts[1], timeouts[2], timeouts[0]]:
            ex[vid].bft_handle_timeout(tmoj)
        assert ex[vid].bft_current_view() == 1

    # Repeat for view=1 with a different quorum subset.
    view2 = 1
    timeouts2: list[dict] = []
    for signer in ["v2", "v3", "v4"]:
        msg = canonical_timeout_message(chain_id="bft-live", view=view2, high_qc_id=high_qc_id, signer=signer)
        sig = sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex")
        tmo = BftTimeout(
            chain_id="bft-live",
            view=view2,
            high_qc_id=high_qc_id,
            signer=signer,
            pubkey=vpub[signer],
            sig=sig,
        )
        assert tmo.verify() is True
        timeouts2.append(tmo.to_json())

    for vid in validators:
        for tmoj in timeouts2:
            ex[vid].bft_handle_timeout(tmoj)
        assert ex[vid].bft_current_view() == 2
