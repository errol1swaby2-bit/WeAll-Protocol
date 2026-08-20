from __future__ import annotations

import pytest

from weall.api.routes_public_parts.status import _local_validator_lifecycle
from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.state_sync import (
    StateSyncService,
    StateSyncVerifyError,
    build_snapshot_anchor,
    sha256_hex_of,
    state_sync_snapshot_view,
)
from weall.runtime.bft_runtime_adapter import BftLeaderProposalError, bft_leader_propose


class _BftCursor:
    view = 0
    last_proposed_view = -1
    last_proposed_block_id = ""
    last_proposed_block_hash = ""


class _FailingLeader:
    def __init__(self) -> None:
        self._bft = _BftCursor()

    def _validator_signing_permitted(self) -> bool:
        return True

    def _active_validators(self) -> list[str]:
        return ["@validator"]

    def _local_validator_account(self) -> str:
        return "@validator"

    def _bft_best_justify_qc_json(self):
        return None

    def build_block_candidate(self, **_kwargs):
        return None, None, [], [], "system_emitter_pre_failed:SystemQueueCorruptionError"


class _NoopExecutor:
    chain_id = "recursive"
    node_id = "node"


class _NoopMempool:
    def peek(self, *_args, **_kwargs):
        return []


class _PollFailureNode:
    def poll(self) -> None:
        raise RuntimeError("poll-boom")


class _StopAfterFailure:
    def __init__(self) -> None:
        self.stopped = False

    def is_set(self) -> bool:
        return self.stopped

    def wait(self, _timeout: float) -> bool:
        self.stopped = True
        return True

    def set(self) -> None:
        self.stopped = True

    def clear(self) -> None:
        self.stopped = False


def _sync_header() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_RESPONSE,
        chain_id="recursive",
        schema_version="1",
        tx_index_hash="tx-index",
        corr_id="recursive-validator-authority",
    )


def _invalid_validator_snapshot() -> dict:
    return {
        "chain_id": "recursive",
        "height": 10,
        "tip": "b10",
        "tip_hash": "h10",
        "finalized": {"height": 9, "block_id": "b9"},
        "params": {"validator_candidate_lifecycle_gate_enabled": True},
        "validators": {
            "registry": {
                "@validator": {
                    "account": "@validator",
                    "status": "active",
                    "pubkey": "canonical-pubkey",
                }
            }
        },
        "consensus": {
            "epochs": {"current": 10},
            "validator_set": {
                "epoch": 3,
                "active_set": ["@validator"],
                # Intentionally omit the consensus BFT verification key while
                # keeping the rest of the snapshot/hash internally coherent.
            },
            "validators": {"registry": {}},
        },
        "system_queue": [],
    }


def test_elected_prod_leader_surfaces_candidate_construction_failure(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    with pytest.raises(
        BftLeaderProposalError,
        match="candidate_build_failed:system_emitter_pre_failed:SystemQueueCorruptionError",
    ):
        bft_leader_propose(_FailingLeader())


def test_state_sync_rejects_validator_authority_state_no_legal_transition_can_create() -> None:
    state = _invalid_validator_snapshot()
    snapshot = state_sync_snapshot_view(state)
    # Build the cryptographic envelope manually so this test proves verification
    # itself rejects the semantic inconsistency, rather than relying only on the
    # local anchor builder to catch it first.
    anchor = {
        "height": 10,
        "tip_hash": "h10",
        "state_root": build_snapshot_anchor({**state, "params": {}})["state_root"],
        "finalized_height": 9,
        "finalized_block_id": "b9",
        "snapshot_hash": sha256_hex_of(snapshot),
    }
    resp = StateSyncResponseMsg(
        header=_sync_header(),
        ok=True,
        reason=None,
        height=10,
        snapshot=snapshot,
        snapshot_hash=anchor["snapshot_hash"],
        snapshot_anchor=anchor,
    )
    svc = StateSyncService(
        chain_id="recursive",
        schema_version="1",
        tx_index_hash="tx-index",
        state_provider=lambda: {},
    )

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:missing_consensus_pubkey:@validator",
    ):
        svc.verify_response(resp, trusted_anchor=anchor)

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:missing_consensus_pubkey:@validator",
    ):
        build_snapshot_anchor(state)


def test_operator_lifecycle_reports_validator_generation_not_protocol_epoch() -> None:
    state = {
        "validators": {"registry": {"@validator": {"status": "active"}}},
        "consensus": {
            "epochs": {"current": 10},
            "validator_set": {
                "epoch": 3,
                "set_hash": "set-3",
                "active_set": ["@validator"],
                "pending": {},
            },
        },
    }

    out = _local_validator_lifecycle(state, "@validator")
    assert out["current_validator_epoch"] == 3


def test_net_thread_wrapper_latches_failure_and_does_not_claim_started(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    loop = NetMeshLoop(
        executor=_NoopExecutor(),
        mempool=_NoopMempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=1,
            schema_version="1",
        ),
    )
    loop.node = _PollFailureNode()
    loop._stop = _StopAfterFailure()
    loop._started = True

    loop._thread_main()

    diag = loop.runtime_debug()
    assert diag["started"] is False
    assert diag["unhealthy"] is True
    assert diag["failure_count"] == 1
    assert "NetLoopRuntimeError:node_poll_failed" in diag["last_error"]
