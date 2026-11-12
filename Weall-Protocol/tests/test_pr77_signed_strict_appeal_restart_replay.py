"""Signed strict-clock ordinary appeal through persisted blocks, restart and replay.

This is a controlled synthetic genesis fixture. Development-only self-bootstrap
provides reviewer PoH; it is NOT independently verified humanity, authenticated
BFT finality, a severe S4 classification, or authority to ban an account.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from weall.crypto.sig import sign_signature_for_profile, sign_tx_envelope_dict
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.ballot_policy import (
    CONTROLLED_TESTNET_BALLOT_PROFILE,
    ballot_profile_status,
)
from weall.runtime.bft_hotstuff import (
    BftVote,
    HotStuffBFT,
    canonical_vote_message,
    quorum_threshold,
    validator_set_hash,
    verify_qc,
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


def _without_local_shutdown_diagnostic(state: dict) -> dict:
    """Normalize only the non-consensus startup diagnostic across executors."""
    stable = deepcopy(state)
    stable["meta"].pop("last_shutdown_clean", None)
    return stable


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

    # Admission rejects client-claimed S4 labels before a case can be
    # committed. Even a genuinely signed allegation is not classification.
    _, reporter_private = _deterministic_replay_fixture_keypair(label=REPORTER)
    untrusted = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": "DISPUTE_OPEN",
            "signer": REPORTER,
            "nonce": 1,
            "payload": {
                "dispute_id": CASE_ID,
                "target_type": "account",
                "target_id": TARGET,
                "reason": "Controlled synthetic ordinary case",
                "sanction_class": "S4",
                "severity": "severe",
            },
        },
        privkey=reporter_private,
        encoding="hex",
    )
    prior_height = source.read_state()["height"]
    refused = source.submit_tx(untrusted)
    assert refused["ok"] is False
    assert refused["reason"] == "schema_validation_failed"
    assert source.read_state()["height"] == prior_height

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
    # The appeal snapshot canonicalizes reviewer IDs into sorted order.
    # Compare membership rather than mistaking that for panel reassignment.
    assert set(appeal["original_panel_juror_ids"]) == set(original)
    assert set(appeal["original_substitute_juror_ids"]) == set(original_subs)
    fresh = list(appeal["appeal_panel_juror_ids"])
    fresh_subs = list(appeal["appeal_substitute_juror_ids"])
    assert len(fresh) == 7
    assert len(fresh_subs) == 2
    assert len(set(fresh + fresh_subs)) == 9
    assert set(fresh + fresh_subs).isdisjoint(original + original_subs)
    assert TARGET not in fresh + fresh_subs
    assert appeal["assigned_jurors"] == fresh
    assert not state["accounts"][TARGET].get("banned", False)
    assert not any(entry.get("tx_type") == "ACCOUNT_BAN" for entry in state.get("system_queue", []))

    # Complete the fresh ordinary appeal using only separately signed and
    # committed juror ACCEPT/VOTE transactions. Do not seed a reached panel
    # verdict or patch a case stage into ledger state.
    appeal_vote_quorum = int(appeal["required_votes"])
    assert 1 <= appeal_vote_quorum <= len(fresh)
    signed_appeal_vote_ids: list[str] = []
    for vote_index, reviewer in enumerate(fresh[:appeal_vote_quorum], start=1):
        _commit_signed(
            source,
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer=reviewer,
            nonce=4,
            payload={"dispute_id": CASE_ID},
        )
        vote_height, signed_vote_id = _commit_signed(
            source,
            tx_type="DISPUTE_VOTE_SUBMIT",
            signer=reviewer,
            nonce=5,
            payload={"dispute_id": CASE_ID, "appeal_decision": "reverse"},
        )
        signed_appeal_vote_ids.append(signed_vote_id)
        recorded = source.read_state()["disputes_by_id"][CASE_ID]
        assert recorded["appeal_panel_votes"] == {}
        assert recorded["appeal_vote_counts"]["reverse"] == vote_index
        assert signed_vote_id in source.get_block_by_height(vote_height)["header"]["tx_ids"]
        if vote_index < appeal_vote_quorum:
            assert recorded["stage"] == "appeal_review"
            assert recorded["appeal_panel_result"]["reached"] is False

    pre_finalization = source.read_state()["disputes_by_id"][CASE_ID]
    assert pre_finalization["stage"] == "appeal_resolved"
    assert pre_finalization["appeal_panel_result"]["reached"] is True
    assert pre_finalization["appeal_panel_result"]["decision"] == "reverse"
    assert pre_finalization["appeal_panel_result"]["resolution"]["decision"] == "reverse"
    assert pre_finalization["appeal_vote_counts"]["reverse"] == appeal_vote_quorum
    assert len(pre_finalization["appeal_voted_juror_ids"]) == appeal_vote_quorum
    assert pre_finalization["appeal_panel_votes"] == {}
    assert pre_finalization["appeal_panel_juror_ids"] == fresh
    assert pre_finalization["appeal_substitute_juror_ids"] == fresh_subs

    # The next production block, with no user transactions, must derive the
    # final receipt from the persisted appeal result through the normal pre
    # scheduler and mandatory SYSTEM queue. This is not a forged SYSTEM input.
    final_height = int(source.read_state()["height"]) + 1
    # Diagnostic witness: distinguish a faulty candidate state-root from a
    # change made after candidate construction while crossing SQLite commit.
    # This wrapper observes the unchanged production methods and does not
    # substitute for their execution or relax any restart invariant.
    original_commit = source.commit_block_candidate
    committed_probe: dict = {}

    def observe_final_commit(
        *, block: dict, new_state: dict, applied_ids: list[str], invalid_ids: list[str]
    ):
        committed_probe["candidate_root"] = compute_state_root(new_state)
        committed_probe["header_root"] = block["header"]["state_root"]
        committed_probe["candidate_state"] = deepcopy(new_state)
        outcome = original_commit(
            block=block, new_state=new_state, applied_ids=applied_ids, invalid_ids=invalid_ids
        )
        committed_probe["post_commit_root"] = compute_state_root(source.state)
        committed_probe["post_commit_state"] = deepcopy(source.state)
        return outcome

    monkeypatch.setattr(source, "commit_block_candidate", observe_final_commit)
    finalized_result = source.produce_block(max_txs=0, allow_empty=True)
    assert finalized_result.ok is True, finalized_result.error
    final_block = source.get_block_by_height(final_height)
    assert isinstance(final_block, dict)
    final_receipts = [
        entry
        for entry in final_block["txs"]
        if entry.get("tx_type") == "DISPUTE_FINAL_RECEIPT"
        and (entry.get("payload") or {}).get("dispute_id") == CASE_ID
    ]
    assert len(final_receipts) == 1
    final_env = final_receipts[0]
    assert final_env["system"] is True
    assert final_env["payload"]["appeal_resolution"] == {
        "decision": "reverse",
    }
    assert final_env["payload"]["_due_height"] == final_height
    assert final_env["payload"]["_system_queue_id"]
    assert final_env["parent"] == f"dispute:{CASE_ID}:appeal-panel-finalize:2"
    final_tx_id = final_env["tx_id"]
    assert final_tx_id in final_block["header"]["tx_ids"]
    assert committed_probe["candidate_root"] == committed_probe["header_root"]
    assert committed_probe["header_root"] == final_block["header"]["state_root"]
    assert committed_probe["post_commit_root"] == committed_probe["header_root"], (
        "post_commit_consensus_fields_changed",
        sorted(
            key
            for key in set(committed_probe["candidate_state"])
            | set(committed_probe["post_commit_state"])
            if committed_probe["candidate_state"].get(key)
            != committed_probe["post_commit_state"].get(key)
            and key not in {"bft", "tip_hash", "tip_ts_ms", "meta"}
        ),
        committed_probe["candidate_root"],
        committed_probe["post_commit_root"],
    )
    assert any(
        receipt.get("tx_id") == final_tx_id and receipt.get("ok") is True
        for receipt in final_block["receipts"]
    )

    state = source.read_state()
    appeal = state["disputes_by_id"][CASE_ID]
    assert appeal["stage"] == "finalized"
    assert appeal["appeal_panel_result"]["decision"] == "reverse"
    assert appeal["appeal_finalization"]["decision"] == "reverse"
    assert appeal["final_resolution"]["appeal_decision"] == "reverse"
    assert appeal["final_resolution"]["actions"] == []
    assert not state["accounts"][TARGET].get("banned", False)
    assert not any(entry.get("tx_type") == "ACCOUNT_BAN" for entry in state.get("system_queue", []))

    source_height = int(state["height"])
    source_root = compute_state_root(state)
    source_blocks = [
        deepcopy(source.get_block_by_height(height)) for height in range(1, source_height + 1)
    ]
    assert all(isinstance(block, dict) for block in source_blocks)
    assert opening_tx_id in source_blocks[opening_height - 1]["header"]["tx_ids"]
    assert appeal_tx_id in source_blocks[appeal_height - 1]["header"]["tx_ids"]
    assert len(signed_appeal_vote_ids) == appeal_vote_quorum
    assert len(set(signed_appeal_vote_ids)) == appeal_vote_quorum
    assert final_tx_id in source_blocks[final_height - 1]["header"]["tx_ids"]

    # A new executor opens the original persisted SQLite, checks its tip and
    # snapshot bindings, then a separate fresh executor applies every block.
    restarted = WeAllExecutor(
        db_path=str(source_path),
        node_id="pr77-strict-source",
        chain_id=CHAIN,
        tx_index_path=str(index),
    )
    # Constructor may revise the local last_shutdown_clean diagnostic while
    # validating its on-disk snapshot. It is excluded from state-root hashing.
    assert _without_local_shutdown_diagnostic(
        restarted.read_state()
    ) == _without_local_shutdown_diagnostic(state)
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

    assert _without_local_shutdown_diagnostic(
        independent.read_state()
    ) == _without_local_shutdown_diagnostic(restarted.read_state())
    assert compute_state_root(independent.read_state()) == source_root
    assert (
        compare_replay_manifests(
            build_replay_manifest(restarted),
            build_replay_manifest(independent),
        )
        == []
    )
    assert independent.read_state()["disputes_by_id"][CASE_ID] == appeal
    assert independent.get_block_by_height(final_height) == final_block
    assert independent.read_state()["disputes_by_id"][CASE_ID]["stage"] == "finalized"
    assert (
        independent.read_state()["disputes_by_id"][CASE_ID]["appeal_finalization"]["decision"]
        == "reverse"
    )
    assert independent.read_state()["disputes_by_id"][CASE_ID]["appeal_panel_votes"] == {}

    # These are offline execution/restart observations, never a BFT QC,
    # independently issued PoH, severe-sanction authority or launch approval.
    assert "sanction_class" not in appeal
    assert not independent.read_state()["accounts"][TARGET].get("banned", False)

    # This BFT cryptographic preflight uses the very same persisted, signed
    # appeal block that independently replayed above. Unlike the TCP count-only
    # rehearsal, each vote is an actual ML-DSA signature verified against a
    # fixed validator registry by TWO fresh HotStuff vote collectors. This is
    # deliberately NOT validator-network finality: votes here are generated
    # by a controlled test harness, not independently transported or witnessed.
    for bypass in ("WEALL_UNSAFE_DEV", "WEALL_BFT_ALLOW_QC_LESS_BLOCKS"):
        monkeypatch.delenv(bypass, raising=False)
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")

    appeal_block = source_blocks[appeal_height - 1]
    proposal_block_id = appeal_block["block_id"]
    proposal_hash = appeal_block["block_hash"]
    proposal_parent = appeal_block["prev_block_id"]
    assert appeal_tx_id in appeal_block["header"]["tx_ids"]
    view = 77
    epoch = 7
    validators = [f"pr77-qc-validator-{n}" for n in range(4)]
    vset_hash = validator_set_hash(validators)
    pubkeys: dict[str, str] = {}
    secrets: dict[str, str] = {}
    for vid in validators:
        pubkeys[vid], secrets[vid] = _deterministic_replay_fixture_keypair(label=vid)

    def make_signed_vote(
        signer: str,
        *,
        vote_epoch: int = epoch,
        voted_hash: str = proposal_hash,
        signing_secret: str | None = None,
    ) -> dict:
        msg = canonical_vote_message(
            chain_id=CHAIN,
            view=view,
            block_id=proposal_block_id,
            block_hash=voted_hash,
            parent_id=proposal_parent,
            signer=signer,
            validator_epoch=vote_epoch,
            validator_set_hash=vset_hash,
            sig_profile=PQ_MLDSA_V1,
        )
        sig = sign_signature_for_profile(
            sig_profile=PQ_MLDSA_V1,
            message=msg,
            privkey=signing_secret or secrets[signer],
        )
        return BftVote(
            chain_id=CHAIN,
            view=view,
            block_id=proposal_block_id,
            block_hash=voted_hash,
            parent_id=proposal_parent,
            signer=signer,
            pubkey=pubkeys[signer],
            sig=sig,
            sig_profile=PQ_MLDSA_V1,
            validator_epoch=vote_epoch,
            validator_set_hash=vset_hash,
        ).to_json()

    def matches_replayed_appeal(vote: dict) -> bool:
        # The candidate has already been checked by BOTH persisted block
        # executors. Pin exact block identity, parent, epoch and validator set
        # before allowing its signed vote into either collector.
        return (
            vote.get("chain_id") == CHAIN
            and vote.get("block_id") == proposal_block_id
            and vote.get("block_hash") == proposal_hash
            and vote.get("parent_id") == proposal_parent
            and vote.get("view") == view
            and vote.get("validator_epoch") == epoch
            and vote.get("validator_set_hash") == vset_hash
        )

    assert quorum_threshold(len(validators)) == 3
    signer_votes = [make_signed_vote(v) for v in validators]
    for v in signer_votes:
        signed_vote = BftVote(
            chain_id=v["chain_id"],
            view=v["view"],
            block_id=v["block_id"],
            block_hash=v["block_hash"],
            parent_id=v["parent_id"],
            signer=v["signer"],
            pubkey=v["pubkey"],
            sig=v["sig"],
            sig_profile=v["sig_profile"],
            validator_epoch=v["validator_epoch"],
            validator_set_hash=v["validator_set_hash"],
        )
        assert signed_vote.verify()

    # A single signer, repeated arbitrarily, is never a quorum.
    no_quorum = HotStuffBFT(chain_id=CHAIN)
    result = no_quorum.accept_vote(
        vote_json=signer_votes[0],
        validators=validators,
        vpub=pubkeys,
        verified_admission=matches_replayed_appeal,
    )
    assert result is None
    result = no_quorum.accept_vote(
        vote_json=signer_votes[0],
        validators=validators,
        vpub=pubkeys,
        verified_admission=matches_replayed_appeal,
    )
    assert result is None
    result = no_quorum.accept_vote(
        vote_json=signer_votes[1],
        validators=validators,
        vpub=pubkeys,
        verified_admission=matches_replayed_appeal,
    )
    assert result is None

    # Distinct in-memory collectors verify the same three signed votes using
    # the same explicit validator registry. Neither is a live remote node.
    collectors = (HotStuffBFT(chain_id=CHAIN), HotStuffBFT(chain_id=CHAIN))
    qcs = []
    for collector in collectors:
        result = collector.accept_vote(
            vote_json=signer_votes[0],
            validators=validators,
            vpub=pubkeys,
            verified_admission=matches_replayed_appeal,
        )
        assert result is None
        result = collector.accept_vote(
            vote_json=signer_votes[1],
            validators=validators,
            vpub=pubkeys,
            verified_admission=matches_replayed_appeal,
        )
        assert result is None
        qc = collector.accept_vote(
            vote_json=signer_votes[2],
            validators=validators,
            vpub=pubkeys,
            verified_admission=matches_replayed_appeal,
        )
        assert qc is not None
        assert verify_qc(qc=qc, validators=validators, vpub=pubkeys)
        assert qc.block_id == proposal_block_id
        assert qc.block_hash == proposal_hash
        assert qc.parent_id == proposal_parent
        assert qc.validator_epoch == epoch
        assert qc.validator_set_hash == vset_hash
        qcs.append(qc)
    assert qcs[0].to_json() == qcs[1].to_json()

    # Changed QC envelope metadata cannot borrow signatures from the signed
    # original block. A self-consistently signed wrong-epoch/wrong-block vote
    # is also refused by the anchored admission callback.
    assert not verify_qc(
        qc=replace(qcs[0], block_hash="0" * 64),
        validators=validators,
        vpub=pubkeys,
    )
    assert not verify_qc(
        qc=replace(qcs[0], validator_epoch=epoch + 1),
        validators=validators,
        vpub=pubkeys,
    )
    rejected = HotStuffBFT(chain_id=CHAIN)
    bad_sig = deepcopy(signer_votes[0])
    bad_sig["sig"] = "00" * 64
    result = rejected.accept_vote(
        vote_json=bad_sig,
        validators=validators,
        vpub=pubkeys,
        verified_admission=matches_replayed_appeal,
    )
    assert result is None
    for forged in (
        make_signed_vote(validators[0], vote_epoch=epoch + 1),
        make_signed_vote(validators[1], voted_hash="0" * 64),
        make_signed_vote(
            validators[2],
            signing_secret=_deterministic_replay_fixture_keypair(
                label="pr77-unregistered-validator"
            )[1],
        ),
    ):
        result = rejected.accept_vote(
            vote_json=forged,
            validators=validators,
            vpub=pubkeys,
            verified_admission=matches_replayed_appeal,
        )
        assert result is None

    # Upgrade the QC test from two standalone HotStuff engines to two
    # independent SQLite-backed WeAllExecutor instances. Seed the simulated
    # validator registry explicitly; doing so is NOT on-chain validator
    # activation or evidence of peer-to-peer network communication.
    monkeypatch.setenv("WEALL_BFT_STRICT_EPOCH_BINDING", "1")
    auditors = []
    for n in range(2):
        auditor_path = tmp_path / f"pr77-qc-auditor-{n}.sqlite"
        auditor = WeAllExecutor(
            db_path=str(auditor_path),
            node_id=f"pr77-qc-auditor-{n}",
            chain_id=CHAIN,
            tx_index_path=str(index),
        )
        configured = deepcopy(auditor.read_state())
        configured.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(
            validators
        )
        consensus = configured.setdefault("consensus", {})
        consensus.setdefault("phase", {})["current"] = "bft_active"
        registry = consensus.setdefault("validators", {}).setdefault("registry", {})
        for vid in validators:
            registry[vid] = {
                "pubkey": pubkeys[vid],
                "sig_profile": PQ_MLDSA_V1,
                "status": "active",
            }
        active_set = consensus.setdefault("validator_set", {})
        active_set["active_set"] = list(validators)
        active_set["epoch"] = epoch
        active_set["set_hash"] = vset_hash
        auditor._ledger_store.write(configured)
        auditor.state = auditor._ledger_store.read()
        auditor._bft.load_from_state(auditor.state)
        assert auditor._active_validators() == validators
        assert auditor._validator_epoch() == (epoch, vset_hash)
        assert auditor.bft_verify_qc_json(qcs[0].to_json()) is not None
        assert (
            auditor.bft_verify_qc_json(replace(qcs[0], validator_epoch=epoch + 1).to_json()) is None
        )
        assert auditor.bft_verify_qc_json(replace(qcs[0], block_hash="0" * 64).to_json()) is None

        # Feed real, authenticated signatures through the production-facing
        # runtime vote ingress rather than HotStuffBFT.accept_vote directly.
        assert auditor.bft_handle_vote(signer_votes[0]) is None
        assert auditor.bft_handle_vote(signer_votes[0]) is None
        assert auditor.bft_handle_vote(signer_votes[1]) is None
        formed = auditor.bft_handle_vote(signer_votes[2])
        assert formed is not None
        assert formed.to_json() == qcs[0].to_json()
        assert auditor.bft_verify_qc_json(formed.to_json()) is not None
        auditors.append((auditor_path, auditor))

    # Restart both independently persisted BFT validators. Their epoch-bound
    # canonical registry and acceptance of the signed QC must survive a
    # process-local executor reinitialization.
    for path, prior_auditor in auditors:
        restarted_auditor = WeAllExecutor(
            db_path=str(path),
            node_id=prior_auditor.node_id,
            chain_id=CHAIN,
            tx_index_path=str(index),
        )
        assert restarted_auditor._validator_epoch() == (epoch, vset_hash)
        assert restarted_auditor._active_validators() == validators
        assert restarted_auditor.bft_verify_qc_json(qcs[0].to_json()) is not None
        assert (
            restarted_auditor.bft_verify_qc_json(
                replace(qcs[0], validator_epoch=epoch + 1).to_json()
            )
            is None
        )

    assert compute_state_root(restarted.read_state()) == source_root
    assert compute_state_root(independent.read_state()) == source_root
    # This is a signed-QC candidate check against a stored ordinary appeal,
    # NOT production proposer/voter transport, QC-driven block commit,
    # externally sourced PoH, network finality, or S4 ban authority.
