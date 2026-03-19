from __future__ import annotations

from pathlib import Path

from weall.crypto.sig import sign_ed25519
from weall.runtime.bft_hotstuff import canonical_vote_message, quorum_threshold
from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_validator_set(
    ex: WeAllExecutor, validators: list[str], pubs: dict[str, str], *, epoch: int = 7
) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = int(epoch)
    c["validator_set"]["set_hash"] = ex._validator_epoch()[1] or ""
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()


def _make_epochless_qc(
    *,
    chain_id: str,
    validators: list[str],
    vpub: dict[str, str],
    vpriv: dict[str, str],
    block_id: str,
    block_hash: str,
    parent_id: str,
    view: int,
) -> dict:
    # Intentionally omit validator_epoch / validator_set_hash at QC level and
    # sign votes with epoch=0 and empty set-hash.
    votes = []
    for signer in validators:
        msg = canonical_vote_message(
            chain_id=chain_id,
            view=int(view),
            block_id=str(block_id),
            block_hash=str(block_hash),
            parent_id=str(parent_id),
            signer=str(signer),
            validator_epoch=0,
            validator_set_hash="",
        )
        sig = sign_ed25519(message=msg, privkey=vpriv[signer], encoding="hex")
        votes.append(
            {
                "t": "VOTE",
                "chain_id": chain_id,
                "view": int(view),
                "block_id": str(block_id),
                "block_hash": str(block_hash),
                "parent_id": str(parent_id),
                "signer": signer,
                "pubkey": vpub[signer],
                "sig": sig,
                "validator_epoch": 0,
                "validator_set_hash": "",
            }
        )
    # Ensure the QC has at least quorum votes.
    votes = votes[: max(quorum_threshold(len(validators)), 1)]
    return {
        "t": "QC",
        "chain_id": chain_id,
        "view": int(view),
        "block_id": str(block_id),
        "block_hash": str(block_hash),
        "parent_id": str(parent_id),
        "votes": votes,
        # NOTE: intentionally missing validator_epoch / validator_set_hash
    }


def test_prod_rejects_epochless_qc_when_epoch_is_set(tmp_path: Path, monkeypatch) -> None:
    # Default mode is production in this test environment.
    tx_index_path = str(Path("generated/tx_index.json"))
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="v1",
        chain_id="bft-prod",
        tx_index_path=tx_index_path,
    )

    validators = ["v1", "v2", "v3", "v4"]
    vpub: dict[str, str] = {}
    vpriv: dict[str, str] = {}
    for vid in validators:
        pub, sk = deterministic_ed25519_keypair(label=vid)
        vpub[vid] = pub
        vpriv[vid] = sk.private_bytes_raw().hex()

    _seed_validator_set(ex, validators, vpub, epoch=7)

    # Build an epoch-less QC for a missing block id.
    qcj = _make_epochless_qc(
        chain_id="bft-prod",
        validators=validators,
        vpub=vpub,
        vpriv=vpriv,
        block_id="missing-block-epochless",
        block_hash="00" * 32,
        parent_id="genesis",
        view=1,
    )

    assert ex.bft_on_qc(qcj) is None
    assert ex.bft_pending_fetch_requests() == []

    # If a caller explicitly disables strict epoch binding (unsafe), the QC can
    # be accepted and should trigger a fetch request. This demonstrates why
    # production bootstrap rejects WEALL_BFT_STRICT_EPOCH_BINDING=0.
    monkeypatch.setenv("WEALL_BFT_STRICT_EPOCH_BINDING", "0")
    assert ex.bft_on_qc(qcj) is None
    assert ex.bft_pending_fetch_requests() == ["missing-block-epochless"]
