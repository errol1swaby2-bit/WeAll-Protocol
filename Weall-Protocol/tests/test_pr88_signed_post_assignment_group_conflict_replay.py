"""PR88 source-bound signed regression: post-assignment group-officer conflict.

Characterizes whether a reviewer legitimately assigned by a strict panel can
subsequently be given group-moderator status through a signed user transaction
and still accept/vote. Replays every committed block on an independent SQLite
executor. Test keys and PoH bootstrap are synthetic development-only fixtures.

A green test is NOT approval of the observed authorization behavior, independent
humanity, juror independence, autonomous BFT finality, or a production release.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.apply.dispute import (
    _dispute_conflict_account_ids,
    _filter_active_dispute_reviewers,
)
from weall.runtime.ballot_policy import CONTROLLED_TESTNET_BALLOT_PROFILE, ballot_profile_status
from weall.runtime.dispute_conflict_provenance_preview import (
    preview_post_assignment_group_conflict,
)
from weall.runtime.dispute_panel_recovery_preview import preview_dispute_panel_recovery
from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import _deterministic_replay_fixture_keypair
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_id import compute_tx_id_from_dict

CHAIN = "weall-controlled-devnet"
REPORTER = "@alice"
GROUP_ID = "pr88-group-conflict"
DISPUTE_ID = "pr88-group-officer-after-panel"


def _controlled_strict_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = root / "configs" / "chains" / "weall-controlled-devnet.json"
    assert manifest.is_file()
    reporter_public, _ = _deterministic_replay_fixture_keypair(label=REPORTER)
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_OPEN", "1")
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_MAX_HEIGHT", "200")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", REPORTER)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", reporter_public)
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


def _signed_committed(
    executor: WeAllExecutor, *, tx_type: str, signer: str, nonce: int, payload: dict
) -> tuple[int, dict]:
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
    submitted = executor.submit_tx(signed)
    assert submitted["ok"] is True, (tx_type, signer, submitted)
    height = int(executor.read_state()["height"]) + 1
    produced = executor.produce_block(max_txs=1)
    assert produced.ok is True, (tx_type, signer, produced.error)
    block = executor.get_block_by_height(height)
    assert isinstance(block, dict)
    assert block["header"]["tx_ids"].count(tx_id) == 1
    receipts = [entry for entry in block["receipts"] if entry.get("tx_id") == tx_id]
    assert len(receipts) == 1
    assert receipts[0]["ok"] is True, (tx_type, signer, receipts)
    assert compute_state_root(executor.read_state()) == block["header"]["state_root"]
    return height, block


def test_signed_group_officer_conflict_after_strict_panel_survives_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _controlled_strict_environment(monkeypatch)
    root = Path(__file__).resolve().parents[1]
    index = root / "generated" / "tx_index.json"
    database = tmp_path / "post-assignment-conflict-producer.sqlite"
    source = WeAllExecutor(
        db_path=str(database),
        node_id="pr88-conflict-producer",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    genesis = source.read_state()
    assert genesis["height"] == 0
    assert genesis["params"]["block_tx_signature_policy"] == "required"
    assert genesis["accounts"][REPORTER]["poh_tier"] == 2
    assert ballot_profile_status(genesis)["strict"] is True
    assert ballot_profile_status(genesis)["active"] is True

    # GROUP_CREATE is a genuine signed user action, not an inserted group
    # record. The creator becomes the initial group signer and moderator.
    _signed_committed(
        source,
        tx_type="GROUP_CREATE",
        signer=REPORTER,
        nonce=1,
        payload={"group_id": GROUP_ID, "charter": "Controlled panel independence regression"},
    )
    group = source.read_state()["roles"]["groups_by_id"][GROUP_ID]
    assert REPORTER in group["signers"]
    assert REPORTER in group["moderators"]

    # Strict low-severity panels require seven jurors and two substitutes.
    # Each account, Tier-2 grant and reviewer opt-in is independently signed
    # and committed, rather than fabricating a reviewer pool in state.
    reviewers = [f"@pr88-juror-{number:02d}" for number in range(9)]
    for reviewer in reviewers:
        public, _ = _deterministic_replay_fixture_keypair(label=reviewer)
        _signed_committed(
            source,
            tx_type="ACCOUNT_REGISTER",
            signer=reviewer,
            nonce=1,
            payload={"pubkey": public},
        )
        _signed_committed(
            source,
            tx_type="POH_BOOTSTRAP_TIER2_GRANT",
            signer=reviewer,
            nonce=2,
            payload={"account_id": reviewer},
        )
        _signed_committed(
            source,
            tx_type="REVIEWER_LANE_OPT_IN",
            signer=reviewer,
            nonce=3,
            payload={"account_id": reviewer, "lane": "dispute_review"},
        )

    opening_height, _ = _signed_committed(
        source,
        tx_type="DISPUTE_OPEN",
        signer=REPORTER,
        nonce=2,
        payload={
            "dispute_id": DISPUTE_ID,
            "target_type": "group",
            "target_id": GROUP_ID,
            "reason": "Controlled signer and reviewer independence",
        },
    )
    opened_state = source.read_state()
    case = opened_state["disputes_by_id"][DISPUTE_ID]
    assert case["panel_status"] == "assigned"
    assert case["stage"] == "juror_review"
    assigned = list(case["assigned_jurors"])
    assert len(assigned) == 7
    assert len(case["substitute_juror_ids"]) == 2
    assert set(assigned + case["substitute_juror_ids"]) == set(reviewers)
    assert not set(assigned).intersection(_dispute_conflict_account_ids(opened_state, case))
    selected = assigned[0]
    assert selected not in group["moderators"]

    # A valid, separately signed GroupSigner action now creates a new live
    # material conflict AFTER the strict panel snapshot was committed.
    before_moderator = deepcopy(source.read_state())
    moderator_height, moderator_block = _signed_committed(
        source,
        tx_type="GROUP_MODERATORS_SET",
        signer=REPORTER,
        nonce=3,
        payload={"group_id": GROUP_ID, "moderators": [REPORTER, selected]},
    )
    assert moderator_height > opening_height
    assert moderator_block["receipts"][0]["ok"] is True
    conflict_state = source.read_state()
    conflicted_case = conflict_state["disputes_by_id"][DISPUTE_ID]
    assert selected in conflict_state["roles"]["groups_by_id"][GROUP_ID]["moderators"]
    assert selected in _dispute_conflict_account_ids(conflict_state, conflicted_case)
    assert selected not in _filter_active_dispute_reviewers(
        deepcopy(conflict_state), list(assigned), deepcopy(conflicted_case)
    )
    assert conflicted_case["jurors"][selected]["status"] == "assigned"
    assert selected in conflicted_case["assigned_jurors"]
    witness = preview_post_assignment_group_conflict(
        before_moderator, conflict_state, moderator_block,
        dispute_id=DISPUTE_ID, juror=selected,
    )
    assert witness["status"] == "candidate_transition_requires_independent_replay"
    assert witness["observed_introduction_height"] == moderator_height
    assert witness["signature_present"] is True
    assert witness["receipt_successful"] is True
    assert witness["independent_replay_verified"] is False
    assert witness["authenticated_conflict_provenance_verified"] is False
    assert witness["recusal_authorized"] is False
    assert before_moderator["height"] == opening_height

    # A claimed receipt or edited block root alone must never be considered
    # independently replayed chain evidence by this advisory observer.
    falsified = deepcopy(moderator_block)
    falsified["header"]["state_root"] = "0" * 64
    assert preview_post_assignment_group_conflict(
        before_moderator, conflict_state, falsified,
        dispute_id=DISPUTE_ID, juror=selected,
    )["status"] == "blocked_state_root_mismatch"
    no_signature = deepcopy(moderator_block)
    for tx in no_signature["txs"]:
        if tx.get("tx_type") == "GROUP_MODERATORS_SET":
            tx["sig"] = ""
            tx.pop("signature", None)
    assert preview_post_assignment_group_conflict(
        before_moderator, conflict_state, no_signature,
        dispute_id=DISPUTE_ID, juror=selected,
    )["status"] == "blocked_unsigned_or_ambiguous_transaction"
    prior_conflict = deepcopy(before_moderator)
    prior_conflict["roles"]["groups_by_id"][GROUP_ID]["moderators"].append(selected)
    assert preview_post_assignment_group_conflict(
        prior_conflict, conflict_state, moderator_block,
        dispute_id=DISPUTE_ID, juror=selected,
    )["status"] == "blocked_preexisting_material_conflict"

    # Characterization of current signed block admission, NOT acceptable
    # constitutional policy. If these receipts fail closed the test pinpoints
    # where the actual gate differs from a direct-applier characterization.
    accepted_height, _ = _signed_committed(
        source,
        tx_type="DISPUTE_JUROR_ACCEPT",
        signer=selected,
        nonce=4,
        payload={"dispute_id": DISPUTE_ID},
    )
    assert accepted_height > moderator_height
    accepted_state = source.read_state()
    assert accepted_state["disputes_by_id"][DISPUTE_ID]["jurors"][selected]["status"] == "accepted"
    assert selected in _dispute_conflict_account_ids(
        accepted_state, accepted_state["disputes_by_id"][DISPUTE_ID]
    )

    vote_height, vote_block = _signed_committed(
        source,
        tx_type="DISPUTE_VOTE_SUBMIT",
        signer=selected,
        nonce=5,
        payload={"dispute_id": DISPUTE_ID, "vote": "no"},
    )
    assert vote_height > accepted_height
    voted_state = source.read_state()
    voted_case = voted_state["disputes_by_id"][DISPUTE_ID]
    assert selected in _dispute_conflict_account_ids(voted_state, voted_case)
    assert voted_case["vote_counts"]["no"] == 1
    assert selected in voted_case["voted_juror_ids"]
    assert voted_case["votes"] == {}
    assert voted_case["jurors"][selected]["status"] == "completed"
    assert any(receipt.get("ok") is True for receipt in vote_block["receipts"])

    # Persisted source and independent replay must agree on every committed
    # block and state root. This is local consensus execution, not BFT finality.
    final_height = int(voted_state["height"])
    final_root = compute_state_root(voted_state)
    blocks = [deepcopy(source.get_block_by_height(h)) for h in range(1, final_height + 1)]
    assert all(isinstance(block, dict) for block in blocks)

    restarted = WeAllExecutor(
        db_path=str(database),
        node_id="pr88-conflict-producer",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    assert compute_state_root(restarted.read_state()) == final_root
    assert restarted.get_block_by_height(final_height) == blocks[-1]

    independent = WeAllExecutor(
        db_path=str(tmp_path / "post-assignment-conflict-follower.sqlite"),
        node_id="pr88-conflict-follower",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    assert independent.read_state()["height"] == 0
    for height, block in enumerate(blocks, start=1):
        replay_before = deepcopy(independent.read_state())
        result = independent.apply_block(deepcopy(block))
        assert result.ok is True, (height, result.error)
        assert independent.get_block_by_height(height) == block
        assert compute_state_root(independent.read_state()) == block["header"]["state_root"]
        if height == moderator_height:
            replay_witness = preview_post_assignment_group_conflict(
                replay_before, independent.read_state(), block,
                dispute_id=DISPUTE_ID, juror=selected,
            )
            assert replay_witness == witness
            assert replay_before == before_moderator
            assert independent.read_state() == conflict_state
    assert compute_state_root(independent.read_state()) == final_root
    assert independent.read_state()["disputes_by_id"][DISPUTE_ID] == voted_case
    assert selected in _dispute_conflict_account_ids(
        independent.read_state(), independent.read_state()["disputes_by_id"][DISPUTE_ID]
    )


def _seed_controlled_v2_genesis(executor: WeAllExecutor) -> str:
    """Development-only genesis override, never an on-chain governance activation."""
    genesis = deepcopy(executor.read_state())
    assert genesis["height"] == 0
    assert "dispute_material_conflict_gate_version" not in genesis["params"]
    genesis["params"]["dispute_material_conflict_gate_version"] = 2
    executor._ledger_store.write(genesis)
    executor.state = executor._ledger_store.read()
    assert executor.read_state()["params"]["dispute_material_conflict_gate_version"] == 2
    return compute_state_root(executor.read_state())


def _signed_rejected_block(
    executor: WeAllExecutor, *, tx_type: str, signer: str, nonce: int, payload: dict
) -> tuple[int, dict]:
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
    submitted = executor.submit_tx(signed)
    assert submitted["ok"] is True, (tx_type, signer, submitted)
    height = int(executor.read_state()["height"]) + 1
    produced = executor.produce_block(max_txs=1)
    assert produced.ok is True, (tx_type, signer, produced.error)
    block = executor.get_block_by_height(height)
    assert isinstance(block, dict)
    assert tx_id in block["header"]["tx_ids"]
    receipts = [entry for entry in block["receipts"] if entry.get("tx_id") == tx_id]
    assert len(receipts) == 1
    assert receipts[0]["ok"] is False, (tx_type, signer, receipts)
    assert "juror_conflict_material" in str(receipts[0]), receipts[0]
    assert compute_state_root(executor.read_state()) == block["header"]["state_root"]
    return height, block


def test_explicit_dev_genesis_v2_rejects_signed_post_assignment_conflict_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opposite signed receipt outcome under explicitly precommitted v2 state.

    V2 is inserted into two matching *test genesis states* before the first
    block because governance param policy intentionally does not whitelist
    activation. It is not a signed governance upgrade or a live-chain release.
    """
    _controlled_strict_environment(monkeypatch)
    index = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    source_path = tmp_path / "material-v2-source.sqlite"
    source = WeAllExecutor(
        db_path=str(source_path),
        node_id="pr88-material-v2-source",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    genesis_root = _seed_controlled_v2_genesis(source)

    _signed_committed(
        source,
        tx_type="GROUP_CREATE",
        signer=REPORTER,
        nonce=1,
        payload={"group_id": GROUP_ID, "charter": "Controlled versioned juror gate"},
    )
    reviewers = [f"@pr88-juror-{number:02d}" for number in range(9)]
    for reviewer in reviewers:
        public, _ = _deterministic_replay_fixture_keypair(label=reviewer)
        _signed_committed(
            source,
            tx_type="ACCOUNT_REGISTER",
            signer=reviewer,
            nonce=1,
            payload={"pubkey": public},
        )
        _signed_committed(
            source,
            tx_type="POH_BOOTSTRAP_TIER2_GRANT",
            signer=reviewer,
            nonce=2,
            payload={"account_id": reviewer},
        )
        _signed_committed(
            source,
            tx_type="REVIEWER_LANE_OPT_IN",
            signer=reviewer,
            nonce=3,
            payload={"account_id": reviewer, "lane": "dispute_review"},
        )

    _signed_committed(
        source,
        tx_type="DISPUTE_OPEN",
        signer=REPORTER,
        nonce=2,
        payload={
            "dispute_id": DISPUTE_ID,
            "target_type": "group",
            "target_id": GROUP_ID,
            "reason": "Controlled v2 conflict rejection",
        },
    )
    opened = source.read_state()["disputes_by_id"][DISPUTE_ID]
    assert opened["panel_status"] == "assigned"
    assert len(opened["assigned_jurors"]) == 7
    selected = opened["assigned_jurors"][0]

    v2_before_moderator = deepcopy(source.read_state())
    v2_moderator_height, v2_moderator_block = _signed_committed(
        source,
        tx_type="GROUP_MODERATORS_SET",
        signer=REPORTER,
        nonce=3,
        payload={"group_id": GROUP_ID, "moderators": [REPORTER, selected]},
    )
    v2_moderator_witness = preview_post_assignment_group_conflict(
        v2_before_moderator, source.read_state(), v2_moderator_block,
        dispute_id=DISPUTE_ID, juror=selected,
    )
    assert v2_moderator_witness["status"] == "candidate_transition_requires_independent_replay"
    assert v2_moderator_witness["observed_introduction_height"] == v2_moderator_height
    assert v2_moderator_witness["recusal_authorized"] is False
    pending = deepcopy(source.read_state()["disputes_by_id"][DISPUTE_ID])
    assert selected in _dispute_conflict_account_ids(source.read_state(), pending)
    assert pending["jurors"][selected]["status"] == "assigned"
    before_preview = deepcopy(source.read_state())
    recovery = preview_dispute_panel_recovery(before_preview, DISPUTE_ID)
    assert recovery["status"] == "candidate_requires_constitutional_review"
    assert recovery["authorized"] is False
    assert recovery["conflicted_assigned_jurors"] == [selected]
    assert recovery["original_panel"] == list(opened["assigned_jurors"])
    assert recovery["required_panel_size"] == 7
    assert recovery["pinned_required_votes"] == opened["required_votes"]
    assert (
        recovery["replacement_candidates"][0]["candidate_substitute"]
        == opened["substitute_juror_ids"][0]
    )
    assert before_preview == source.read_state()

    # Canonical attendance is SYSTEM-only/receipt-only and cannot be
    # submitted by a juror through signed user ingress. This is NOT an
    # additional user-origin v2 acceptance bypass.
    _, private = _deterministic_replay_fixture_keypair(label=selected)
    attendance_signed = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": "DISPUTE_JUROR_ATTENDANCE",
            "signer": selected,
            "nonce": 4,
            "payload": {"dispute_id": DISPUTE_ID, "present": True},
        },
        privkey=private,
        encoding="hex",
    )
    admission_height = int(source.read_state()["height"])
    denied = source.submit_tx(attendance_signed)
    assert denied["ok"] is False
    assert (denied.get("error"), denied.get("reason")) == (
        "system_tx_forbidden",
        "system_flag_required",
    )
    assert int(source.read_state()["height"]) == admission_height
    assert source.read_state()["disputes_by_id"][DISPUTE_ID] == pending

    accept_height, accept_block = _signed_rejected_block(
        source,
        tx_type="DISPUTE_JUROR_ACCEPT",
        signer=selected,
        nonce=4,
        payload={"dispute_id": DISPUTE_ID},
    )
    assert accept_height > admission_height
    assert accept_block["header"]["state_root"] == compute_state_root(source.read_state())
    assert source.read_state()["disputes_by_id"][DISPUTE_ID] == pending

    vote_height, vote_block = _signed_rejected_block(
        source,
        tx_type="DISPUTE_VOTE_SUBMIT",
        signer=selected,
        nonce=5,
        payload={"dispute_id": DISPUTE_ID, "vote": "no"},
    )
    assert vote_height > accept_height
    assert vote_block["header"]["state_root"] == compute_state_root(source.read_state())
    assert source.read_state()["disputes_by_id"][DISPUTE_ID] == pending
    assert selected not in pending.get("voted_juror_ids", [])
    assert pending.get("vote_counts", {}).get("no", 0) == 0

    # Rejection of a conflicted juror must not freeze a legitimately appointed
    # member of the same strict panel. Exercise a different, unconflicted
    # juror through signed acceptance and a deattributed, counted ballot.
    unconflicted = next(j for j in opened["assigned_jurors"] if j != selected)
    assert unconflicted not in _dispute_conflict_account_ids(source.read_state(), pending)
    good_accept_height, _ = _signed_committed(
        source,
        tx_type="DISPUTE_JUROR_ACCEPT",
        signer=unconflicted,
        nonce=4,
        payload={"dispute_id": DISPUTE_ID},
    )
    assert good_accept_height > vote_height
    assert (
        source.read_state()["disputes_by_id"][DISPUTE_ID]["jurors"][unconflicted]["status"]
        == "accepted"
    )
    good_vote_height, _ = _signed_committed(
        source,
        tx_type="DISPUTE_VOTE_SUBMIT",
        signer=unconflicted,
        nonce=5,
        payload={"dispute_id": DISPUTE_ID, "vote": "yes"},
    )
    assert good_vote_height > good_accept_height
    completed = source.read_state()["disputes_by_id"][DISPUTE_ID]
    assert completed["jurors"][unconflicted]["status"] == "completed"
    assert completed["vote_counts"]["yes"] == 1
    assert completed.get("vote_counts", {}).get("no", 0) == 0
    assert unconflicted in completed["voted_juror_ids"]
    assert selected not in completed["voted_juror_ids"]
    assert completed["votes"] == {}
    post_ballot = preview_dispute_panel_recovery(source.read_state(), DISPUTE_ID)
    # The dormant v2 candidate must retain a fixed seven-juror threshold
    # despite losing one eligible juror. The affected panel is incomplete;
    # do not schedule resolution even if other jurors submit five votes.
    assert len(completed["assigned_jurors"]) == 7
    assert opened["required_votes"] == 5
    assert completed["eligible_validator_count"] == 6
    assert completed["required_votes"] == 5
    assert post_ballot["status"] == "blocked_existing_ballots"
    assert post_ballot["ballots_already_present"] is True
    assert post_ballot["minimum_required_votes"] == 5
    assert post_ballot["pinned_required_votes"] == 5

    other_unconflicted = [
        juror for juror in opened["assigned_jurors"] if juror not in {selected, unconflicted}
    ]
    assert len(other_unconflicted) == 5
    for signer in other_unconflicted[:4]:
        _signed_committed(
            source,
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer=signer,
            nonce=4,
            payload={"dispute_id": DISPUTE_ID},
        )
        _signed_committed(
            source,
            tx_type="DISPUTE_VOTE_SUBMIT",
            signer=signer,
            nonce=5,
            payload={"dispute_id": DISPUTE_ID, "vote": "yes"},
        )
    completed = source.read_state()["disputes_by_id"][DISPUTE_ID]
    assert completed["vote_counts"]["yes"] == 5
    assert completed["required_votes"] == 5
    assert completed["eligible_validator_count"] == 6
    assert len(completed["assigned_jurors"]) == 7
    assert completed["resolved"] is False
    assert completed["stage"] == "juror_review"
    assert (
        preview_dispute_panel_recovery(source.read_state(), DISPUTE_ID)["status"]
        == "blocked_existing_ballots"
    )

    final_state = source.read_state()
    final_root = compute_state_root(final_state)
    height = int(final_state["height"])
    blocks = [deepcopy(source.get_block_by_height(i)) for i in range(1, height + 1)]
    assert all(isinstance(block, dict) for block in blocks)

    restarted = WeAllExecutor(
        db_path=str(source_path),
        node_id="pr88-material-v2-source",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    assert restarted.read_state()["params"]["dispute_material_conflict_gate_version"] == 2
    assert compute_state_root(restarted.read_state()) == final_root

    independent = WeAllExecutor(
        db_path=str(tmp_path / "material-v2-independent.sqlite"),
        node_id="pr88-material-v2-independent",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    assert _seed_controlled_v2_genesis(independent) == genesis_root
    for number, block in enumerate(blocks, start=1):
        replay_before = deepcopy(independent.read_state())
        applied = independent.apply_block(deepcopy(block))
        assert applied.ok is True, (number, applied.error)
        assert independent.get_block_by_height(number) == block
        assert compute_state_root(independent.read_state()) == block["header"]["state_root"]
        if number == v2_moderator_height:
            assert replay_before == v2_before_moderator
            assert preview_post_assignment_group_conflict(
                replay_before, independent.read_state(), block,
                dispute_id=DISPUTE_ID, juror=selected,
            ) == v2_moderator_witness
    assert compute_state_root(independent.read_state()) == final_root
    assert independent.read_state()["disputes_by_id"][DISPUTE_ID] == completed
    assert independent.read_state()["disputes_by_id"][DISPUTE_ID]["vote_counts"]["yes"] == 5


def test_mismatched_test_genesis_v2_cannot_replay_v1_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Do not silently reinterpret v1 block history from a changed genesis root."""
    _controlled_strict_environment(monkeypatch)
    index = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    legacy = WeAllExecutor(
        db_path=str(tmp_path / "legacy-genesis.sqlite"),
        node_id="pr88-legacy-genesis",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    v2_follower = WeAllExecutor(
        db_path=str(tmp_path / "v2-genesis.sqlite"),
        node_id="pr88-v2-genesis",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    legacy_genesis_root = compute_state_root(legacy.read_state())
    v2_genesis_root = _seed_controlled_v2_genesis(v2_follower)
    assert legacy_genesis_root != v2_genesis_root

    _, legacy_block = _signed_committed(
        legacy,
        tx_type="GROUP_CREATE",
        signer=REPORTER,
        nonce=1,
        payload={"group_id": GROUP_ID, "charter": "Historical genesis incompatibility probe"},
    )
    before = deepcopy(v2_follower.read_state())
    applied = v2_follower.apply_block(deepcopy(legacy_block))
    assert applied.ok is False, "cross-genesis replay must reject an incompatible state root"
    assert compute_state_root(v2_follower.read_state()) == v2_genesis_root
    assert v2_follower.read_state() == before
