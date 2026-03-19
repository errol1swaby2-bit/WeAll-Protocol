from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor
from weall.testing.sigtools import deterministic_ed25519_keypair


def _seed_validator_set(ex: WeAllExecutor, validators: list[str], pubs: dict[str, str]) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(validators)
    c = st.setdefault("consensus", {})
    c.setdefault("validators", {}).setdefault("registry", {})
    for v in validators:
        c["validators"]["registry"].setdefault(v, {})["pubkey"] = pubs[v]
    c.setdefault("validator_set", {})["active_set"] = list(validators)
    c["validator_set"]["epoch"] = 7
    c["validator_set"]["set_hash"] = ex._validator_epoch()[1] or ""
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()


def _mk_validators() -> tuple[list[str], dict[str, str], dict[str, str]]:
    validators = ["v1", "v2", "v3", "v4"]
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for vid in validators:
        pub, sk = deterministic_ed25519_keypair(label=vid)
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    return validators, pubs, privs


def test_invalid_remote_proposal_stays_quarantined_not_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validators, pubs, _privs = _mk_validators()
    tx_index_path = str(Path("generated/tx_index.json"))
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="v2",
        chain_id="bft-prod",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(follower, validators, pubs)

    monkeypatch.setenv("WEALL_SIGVERIFY", "1")

    proposal = {
        "chain_id": "bft-prod",
        "block_id": "blk-bad",
        "block_hash": "ab" * 32,
        "height": 1,
        "view": 1,
        "proposer": "v2",
        "validator_epoch": 7,
        "validator_set_hash": follower._validator_epoch()[1],
        "header": {
            "chain_id": "bft-prod",
            "height": 1,
            "prev_block_hash": "",
            "block_ts_ms": 1,
            "tx_ids": [],
            "receipts_root": "11" * 32,
            "state_root": "22" * 32,
        },
        "txs": [],
        "proposer_pubkey": pubs["v2"],
        "proposer_sig": "00",
    }

    assert follower.bft_on_proposal(proposal) is None
    assert "blk-bad" not in follower._pending_remote_blocks
    assert "blk-bad" in follower._quarantined_remote_blocks


def test_valid_remote_proposal_promotes_from_quarantine_to_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validators, pubs, privs = _mk_validators()
    tx_index_path = str(Path("generated/tx_index.json"))

    leader = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="v2",
        chain_id="bft-prod",
        tx_index_path=tx_index_path,
    )
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="v1",
        chain_id="bft-prod",
        tx_index_path=tx_index_path,
    )
    _seed_validator_set(leader, validators, pubs)
    _seed_validator_set(follower, validators, pubs)

    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "v2")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", pubs["v2"])
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", privs["v2"])

    leader.bft_set_view(1)
    proposal = leader.bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict)

    follower._validate_remote_proposal_for_vote = lambda block: False
    assert follower.bft_on_proposal(dict(proposal)) is None

    bid = str(proposal["block_id"])
    assert bid in follower._pending_remote_blocks
    assert bid not in follower._quarantined_remote_blocks

    diag = follower.bft_diagnostics()
    assert diag["pending_remote_blocks_count"] >= 1
    assert diag["quarantined_remote_blocks_count"] == 0
