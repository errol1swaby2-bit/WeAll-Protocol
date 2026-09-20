from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_vote_anti_equivocation_binds_exact_block_hash() -> None:
    bft = HotStuffBFT(chain_id="artifact-identity")

    assert bft.record_local_vote(view=7, block_id="B7", block_hash="hash-a") is True
    assert bft.record_local_vote(view=7, block_id="B7", block_hash="hash-a") is True
    assert bft.record_local_vote(view=7, block_id="B7", block_hash="hash-b") is False

    state = bft.export_state()
    assert state["last_voted_block_id"] == "B7"
    assert state["last_voted_block_hash"] == "hash-a"


def test_proposal_anti_equivocation_binds_exact_block_hash_across_restart() -> None:
    first = HotStuffBFT(chain_id="artifact-identity")
    assert (
        first.record_local_proposal(view=11, block_id="B11", block_hash="proposal-hash-a") is True
    )

    restored = HotStuffBFT(chain_id="artifact-identity")
    restored.load_from_state({"bft": first.export_state()})

    assert (
        restored.record_local_proposal(view=11, block_id="B11", block_hash="proposal-hash-a")
        is True
    )
    assert (
        restored.record_local_proposal(view=11, block_id="B11", block_hash="proposal-hash-b")
        is False
    )
    assert restored.last_proposed_block_hash == "proposal-hash-a"


def test_legacy_same_view_cursor_without_hash_fails_closed_for_hashed_artifact() -> None:
    restored = HotStuffBFT(chain_id="artifact-identity")
    restored.load_from_state(
        {
            "bft": {
                "last_voted_view": 5,
                "last_voted_block_id": "legacy-vote",
                "last_proposed_view": 5,
                "last_proposed_block_id": "legacy-proposal",
            }
        }
    )

    assert (
        restored.record_local_vote(view=5, block_id="legacy-vote", block_hash="new-hash") is False
    )
    assert (
        restored.record_local_proposal(view=5, block_id="legacy-proposal", block_hash="new-hash")
        is False
    )

    # A higher view establishes a fully bound cursor normally.
    assert restored.record_local_vote(view=6, block_id="vote-6", block_hash="hash-6") is True
    assert (
        restored.record_local_proposal(view=6, block_id="proposal-6", block_hash="hash-6") is True
    )


def test_same_view_leader_retry_reuses_exact_pending_proposal() -> None:
    from types import SimpleNamespace

    from weall.runtime.bft_runtime_adapter import bft_leader_propose

    block = {
        "block_id": "B0",
        "block_hash": "hash-0",
        "view": 0,
        "proposer": "@validator",
    }

    class _FakeLeader:
        _bft = SimpleNamespace(
            view=0,
            last_proposed_view=0,
            last_proposed_block_id="B0",
            last_proposed_block_hash="hash-0",
        )
        _pending_candidates = {"B0": (block, {}, [], [])}

        def _validator_signing_permitted(self) -> bool:
            return True

        def _active_validators(self) -> list[str]:
            return ["@validator"]

        def _local_validator_account(self) -> str:
            return "@validator"

        def build_block_candidate(self, **_kwargs):
            raise AssertionError("same-view retry must not rebuild a proposal")

    replay = bft_leader_propose(_FakeLeader(), max_txs=7)
    assert replay == block


def test_same_view_leader_retry_fails_closed_without_exact_pending_hash() -> None:
    from types import SimpleNamespace

    from weall.runtime.bft_runtime_adapter import bft_leader_propose

    block = {
        "block_id": "B0",
        "block_hash": "different-hash",
        "view": 0,
        "proposer": "@validator",
    }

    class _FakeLeader:
        _bft = SimpleNamespace(
            view=0,
            last_proposed_view=0,
            last_proposed_block_id="B0",
            last_proposed_block_hash="hash-0",
        )
        _pending_candidates = {"B0": (block, {}, [], [])}

        def _validator_signing_permitted(self) -> bool:
            return True

        def _active_validators(self) -> list[str]:
            return ["@validator"]

        def _local_validator_account(self) -> str:
            return "@validator"

    assert bft_leader_propose(_FakeLeader(), max_txs=7) is None
