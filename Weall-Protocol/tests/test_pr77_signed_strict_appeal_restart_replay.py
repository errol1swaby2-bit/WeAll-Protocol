"""Signed strict-clock ordinary appeal through persisted blocks, restart and replay.

This is a controlled synthetic genesis fixture. Development-only self-bootstrap
provides reviewer PoH; it is NOT independently verified humanity, authenticated
BFT finality, a severe S4 classification, or authority to ban an account.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.ballot_policy import (
    CONTROLLED_TESTNET_BALLOT_PROFILE,
    ballot_profile_status,
)
from weall.runtime.constitutional_clock import policy_from_state
from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import (
    _deterministic_replay_fixture_keypair,
    build_replay_manifest,
    compare_replay_manifests,
)
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_id import compute_tx_id_from_dict

CHAIN = "weall-controlled-devnet"
CASE_ID = "pr77-signed-strict-appeal"
REPORTER = "@alice"
TARGET = "@bob"


def _commit_signed(
    executor: WeAllExecutor,
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
) -> tuple[int, str]:
    _, private = _deterministic_replay_fixture_keypair(label=signer)
    signed = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
        },
        privkey=private,
        encoding="hex",
    )
    tx_id = compute_tx_id_from_dict(CHAIN, signed)
    admission = executor.submit_tx(signed)
    assert admission["ok"] is True, (tx_type, signer, admission)
    height = int(executor.read_state()["height"]) + 1
    produced = executor.produce_block(max_txs=1)
    assert produced.ok is True, (tx_type, signer, produced.error)
    stored = executor.get_block_by_height(height)
    assert isinstance(stored, dict)
    assert stored["header"]["tx_ids"].count(tx_id) == 1
    receipts = [r for r in stored["receipts"] if r.get("tx_id") == tx_id]
    assert len(receipts) == 1
    assert receipts[0]["ok"] is True, (tx_type, signer, receipts)
    return height, tx_id


def _fixture_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = root / "configs" / "chains" / "weall-controlled-devnet.json"
    assert manifest.is_file()
    alice_pub, _ = _deterministic_replay_fixture_keypair(label=REPORTER)

    # Deliberate non-production bootstrap. The active governance/ballot profile
    # and the chain manifest remain consensus-visible and strict.
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_OPEN", "1")
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_MAX_HEIGHT", "200")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", REPORTER)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", alice_pub)
    monkeypatch.setenv("WEALL_M3_CIVIC_GOVERNANCE_STRICT", "1")
    monkeypatch.setenv("WEALL_BALLOT_PROFILE_ID", CONTROLLED_TESTNET_BALLOT_PROFILE)
    monkeypatch.setenv("WEALL_BALLOT_PROFILE_ACTIVE", "1")
    for key in (
        "WEALL_GENESIS_MODE",
        "WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE",
        "WEALL_NODE_ID",
        "WEALL_VALIDATOR_ACCOUNT",
    ):
        monkeypatch.delenv(key, raising=False)


def test_signed_strict_appeal_survives_db_restart_and_independent_block_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture_environment(monkeypatch)
    root = Path(__file__).resolve().parents[1]
    index = root / "generated" / "tx_index.json"
    source_path = tmp_path / "strict-appeal-source.sqlite"
    source = WeAllExecutor(
        db_path=str(source_path),
        node_id="pr77-strict-source",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    genesis = source.read_state()
    assert genesis["height"] == 0
    assert genesis["accounts"][REPORTER]["poh_tier"] == 2
    assert genesis["params"]["poh_bootstrap_open"] is True
    assert genesis["params"]["block_tx_signature_policy"] == "required"
    assert ballot_profile_status(genesis)["strict"] is True
    assert ballot_profile_status(genesis)["active"] is True

    target_pub, _ = _deterministic_replay_fixture_keypair(label=TARGET)
    _commit_signed(
        source,
        tx_type="ACCOUNT_REGISTER",
        signer=TARGET,
        nonce=1,
        payload={"pubkey": target_pub},
    )
    _commit_signed(
        source,
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer=TARGET,
        nonce=2,
        payload={"account_id": TARGET},
    )
    assert policy_from_state(source.read_state()).enabled is True

    # Establish the entire reviewer pool from actual signed, committed
    # transactions; never write an invented panel or appeal_window into state.
    reviewers = [f"@juror-{n:02d}" for n in range(18)]
    for reviewer in reviewers:
        pub, _ = _deterministic_replay_fixture_keypair(label=reviewer)
        _commit_signed(
            source,
            tx_type="ACCOUNT_REGISTER",
            signer=reviewer,
            nonce=1,
            payload={"pubkey": pub},
        )
        _commit_signed(
            source,
            tx_type="POH_BOOTSTRAP_TIER2_GRANT",
            signer=reviewer,
            nonce=2,
            payload={"account_id": reviewer},
        )
        _commit_signed(
            source,
            tx_type="REVIEWER_LANE_OPT_IN",
            signer=reviewer,
            nonce=3,
            payload={"account_id": reviewer, "lane": "dispute_review"},
        )

    opening_height, opening_tx_id = _commit_signed(
        source,
        tx_type="DISPUTE_OPEN",
        signer=REPORTER,
        nonce=1,
        payload={
            "dispute_id": CASE_ID,
            "target_type": "account",
            "target_id": TARGET,
            "reason": "Controlled synthetic ordinary case",
            "sanction_class": "S4",
            "severity": "severe",
        },
    )
    opened = source.read_state()["disputes_by_id"][CASE_ID]
    assert opened["opened_at_height"] == opening_height - 1
    # User-supplied S4 labels are not canonical classification authority.
    assert "sanction_class" not in opened
    assert "severity" not in opened
    assert opened["stage"] == "juror_review"
    assert opened["panel_status"] == "assigned"
    original = list(opened["assigned_jurors"])
    original_subs = list(opened["substitute_juror_ids"])
    assert len(original) == 7
    assert len(original_subs) == 2
    assert len(set(original + original_subs)) == 9
    assert not {REPORTER, TARGET}.intersection(original + original_subs)

    # The ledger itself opens the appeal window from signed juror ballots.
    required = int(opened["required_votes"])
    assert 1 <= required <= len(original)
    for reviewer in original[:required]:
        _commit_signed(
            source,
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer=reviewer,
            nonce=4,
            payload={"dispute_id": CASE_ID},
        )
        _commit_signed(
            source,
            tx_type="DISPUTE_VOTE_SUBMIT",
            signer=reviewer,
            nonce=5,
            payload={"dispute_id": CASE_ID, "vote": "no"},
        )
    decided = source.read_state()["disputes_by_id"][CASE_ID]
    assert decided["resolved"] is True
    assert decided["stage"] == "appeal_window"
    assert decided["resolution"]["outcome"] == "report_not_upheld"

    appeal_height, appeal_tx_id = _commit_signed(
        source,
        tx_type="DISPUTE_APPEAL",
        signer=TARGET,
        nonce=3,
        payload={"dispute_id": CASE_ID, "reason": "Independent signed review"},
    )
    state = source.read_state()
    appeal = state["disputes_by_id"][CASE_ID]
    assert appeal["stage"] == "appeal_review"
    assert appeal["appeals"][0]["by"] == TARGET
    assert appeal["appeals"][0]["at_nonce"] == 3
    assert appeal["appeals"][0]["height"] == appeal_height - 1
    assert appeal["original_panel_juror_ids"] == original
    assert appeal["original_substitute_juror_ids"] == original_subs
    fresh = list(appeal["appeal_panel_juror_ids"])
    fresh_subs = list(appeal["appeal_substitute_juror_ids"])
    assert len(fresh) == 7
    assert len(fresh_subs) == 2
    assert len(set(fresh + fresh_subs)) == 9
    assert set(fresh + fresh_subs).isdisjoint(original + original_subs)
    assert TARGET not in fresh + fresh_subs
    assert appeal["assigned_jurors"] == fresh
    assert not state["accounts"][TARGET].get("banned", False)
    assert not any(
        entry.get("tx_type") == "ACCOUNT_BAN"
        for entry in state.get("system_queue", [])
    )

    source_height = int(state["height"])
    source_root = compute_state_root(state)
    source_blocks = [
        deepcopy(source.get_block_by_height(height))
        for height in range(1, source_height + 1)
    ]
    assert all(isinstance(block, dict) for block in source_blocks)
    assert opening_tx_id in source_blocks[opening_height - 1]["header"]["tx_ids"]
    assert appeal_tx_id in source_blocks[appeal_height - 1]["header"]["tx_ids"]

    # A new executor opens the original persisted SQLite, checks its tip and
    # snapshot bindings, then a separate fresh executor applies every block.
    restarted = WeAllExecutor(
        db_path=str(source_path),
        node_id="pr77-strict-source",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    assert restarted.read_state() == state
    assert compute_state_root(restarted.read_state()) == source_root
    assert restarted.get_block_by_height(appeal_height) == source_blocks[appeal_height - 1]

    independent = WeAllExecutor(
        db_path=str(tmp_path / "strict-appeal-independent.sqlite"),
        node_id="pr77-strict-independent",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    assert independent.read_state()["height"] == 0
    for height, block in enumerate(source_blocks, start=1):
        applied = independent.apply_block(deepcopy(block))
        assert applied.ok is True, (height, applied.error)
        assert independent.get_block_by_height(height) == block
        assert compute_state_root(independent.read_state()) == block["header"]["state_root"]

    assert independent.read_state() == restarted.read_state()
    assert compute_state_root(independent.read_state()) == source_root
    assert compare_replay_manifests(
        build_replay_manifest(restarted),
        build_replay_manifest(independent),
    ) == []
    assert independent.read_state()["disputes_by_id"][CASE_ID] == appeal

    # These are offline execution/restart observations, never a BFT QC,
    # independently issued PoH, severe-sanction authority or launch approval.
    assert "sanction_class" not in appeal
    assert not independent.read_state()["accounts"][TARGET].get("banned", False)
