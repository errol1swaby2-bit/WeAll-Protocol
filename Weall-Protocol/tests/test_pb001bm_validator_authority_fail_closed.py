from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.api.routes_nodes import _active_validators_from_state as api_active_validators
from weall.api.routes_public_parts.status import _active_validators as status_active_validators
from weall.ledger.state import LedgerView
from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.node import NetNode
from weall.net.state_sync import (
    StateSyncService,
    StateSyncVerifyError,
    build_snapshot_anchor,
    sha256_hex_of,
    state_sync_snapshot_view,
)
from weall.runtime import bft_runtime_adapter, block_admission
from weall.runtime.apply.consensus import (
    CONSENSUS_PHASE_BFT_ACTIVE,
    _read_consensus_phase_without_mutation,
)
from weall.runtime.apply.consensus import (
    _active_validator_accounts as consensus_active_validators,
)
from weall.runtime.apply.content import _active_validator_accounts as content_active_validators
from weall.runtime.apply.dispute import _active_validator_ids as dispute_active_validators
from weall.runtime.apply.governance import _active_validator_ids as governance_active_validators
from weall.runtime.apply.poh import _active_validator_count_for_bootstrap_sunset
from weall.runtime.block_loop import _active_validators_from_executor
from weall.runtime.bootstrap_manifest import validator_epoch_and_hash
from weall.runtime.gate_expr import _is_validator
from weall.runtime.poh.bootstrap_quorum import active_validator_count
from weall.runtime.state_hash import compute_state_root


def _state(*, active_set: object = "not-a-list", epoch: object = "not-an-int") -> dict:
    return {
        "chain_id": "pb001bm",
        "height": 10,
        "tip": "b10",
        "tip_hash": "h10",
        "finalized": {"height": 9, "block_id": "b9"},
        "params": {"validator_candidate_lifecycle_gate_enabled": True},
        "accounts": {
            "stale": {"poh_tier": 2},
            "new": {"poh_tier": 2},
        },
        "validators": {
            "registry": {
                "stale": {"account": "stale", "status": "active", "pubkey": "pk-stale"},
                "new": {"account": "new", "status": "active", "pubkey": "pk-new"},
            }
        },
        "roles": {
            "validators": {
                "active_set": ["stale"],
                "by_id": {"stale": {"active": True, "status": "active"}},
            }
        },
        "consensus": {
            "epochs": {"current": 9},
            "validator_set": {
                "epoch": epoch,
                "active_set": active_set,
                "set_hash": "stale-set-hash",
            },
            "validators": {
                "registry": {
                    "stale": {"status": "active", "pubkey": "pk-stale"},
                    "new": {"status": "active", "pubkey": "pk-new"},
                }
            },
        },
        "system_queue": [],
    }


def _response_for(snapshot: dict) -> tuple[StateSyncService, StateSyncResponseMsg, dict]:
    transferable = state_sync_snapshot_view(snapshot)
    anchor = {
        "height": 10,
        "tip_hash": "h10",
        "state_root": compute_state_root(snapshot),
        "finalized_height": 9,
        "finalized_block_id": "b9",
        "snapshot_hash": sha256_hex_of(transferable),
    }
    response = StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id="pb001bm",
            schema_version="1",
            tx_index_hash="tx-index",
            corr_id="pb001bm-authority",
        ),
        ok=True,
        reason=None,
        height=10,
        snapshot=transferable,
        snapshot_hash=anchor["snapshot_hash"],
        snapshot_anchor=anchor,
    )
    service = StateSyncService(
        chain_id="pb001bm",
        schema_version="1",
        tx_index_hash="tx-index",
        state_provider=lambda: {},
    )
    return service, response, anchor


def test_state_sync_rejects_malformed_materialized_validator_membership() -> None:
    state = _state(epoch=3)
    service, response, anchor = _response_for(state)

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:active_set_not_list",
    ):
        service.verify_response(response, trusted_anchor=anchor)

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:validator_epoch_invalid|snapshot_validator_authority_invalid:active_set_not_list",
    ):
        build_snapshot_anchor(state)


def test_state_sync_rejects_malformed_declared_validator_generation() -> None:
    state = _state(active_set=["new"], epoch="not-an-int")
    service, response, anchor = _response_for(state)

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:validator_epoch_invalid",
    ):
        service.verify_response(response, trusted_anchor=anchor)


def test_malformed_materialized_membership_never_reactivates_legacy_authority() -> None:
    state = _state()
    executor = SimpleNamespace(state=state)
    node = SimpleNamespace(_get_ledger=lambda state=state: state)

    assert block_admission._get_active_validators_from_state(state) == []
    assert bft_runtime_adapter._active_validators(executor) == []
    assert _active_validators_from_executor(executor) == []
    assert LedgerView.from_ledger(state).get_active_validator_set() == []
    assert NetNode._is_validator(node, state, "stale") is False
    assert _is_validator(state, "stale") is False
    assert status_active_validators(state) == []
    assert api_active_validators(state) == []
    assert active_validator_count(state) == 0
    assert _active_validator_count_for_bootstrap_sunset(state) == 0
    assert content_active_validators(state) == []
    assert dispute_active_validators(state) == []
    assert governance_active_validators(state) == []
    assert consensus_active_validators(state) == []
    assert _read_consensus_phase_without_mutation(state) != CONSENSUS_PHASE_BFT_ACTIVE

    manifest_epoch, _, manifest_validators = validator_epoch_and_hash(state)
    assert manifest_epoch == 0
    assert manifest_validators == []


def test_malformed_or_explicit_zero_generation_never_falls_back_to_protocol_epoch() -> None:
    for raw_epoch in ("not-an-int", 0):
        state = _state(active_set=["new"], epoch=raw_epoch)
        executor = SimpleNamespace(state=state)
        node = SimpleNamespace(_get_ledger=lambda state=state: state)

        assert block_admission._current_validator_epoch_from_state(state) == 0
        assert bft_runtime_adapter._current_validator_epoch(executor) == 0
        assert NetNode._handshake_validator_epoch(node) == 0
        assert validator_epoch_and_hash(state)[0] == 0


def test_legacy_fallback_remains_available_only_when_canonical_fields_are_undeclared() -> None:
    state = _state()
    state["consensus"]["validator_set"] = {}
    executor = SimpleNamespace(state=state)
    node = SimpleNamespace(_get_ledger=lambda: state)

    assert block_admission._get_active_validators_from_state(state) == ["stale"]
    assert bft_runtime_adapter._active_validators(executor) == ["stale"]
    assert NetNode._is_validator(node, state, "stale") is True
    assert block_admission._current_validator_epoch_from_state(state) == 9
    assert bft_runtime_adapter._current_validator_epoch(executor) == 9
    assert NetNode._handshake_validator_epoch(node) == 9


def test_state_sync_rejects_non_object_materialized_validator_set() -> None:
    state = _state()
    state["consensus"]["validator_set"] = "corrupt"
    service, response, anchor = _response_for(state)

    with pytest.raises(
        StateSyncVerifyError,
        match="snapshot_validator_authority_invalid:validator_set_not_object",
    ):
        service.verify_response(response, trusted_anchor=anchor)
