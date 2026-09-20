from __future__ import annotations

import copy

from weall.runtime.consensus_profile_manifest import (
    consensus_activation_projection,
    consensus_profile_mismatch_reasons,
    load_consensus_profile_manifest,
)


def _base_state() -> dict:
    return {
        "chain_id": "weall-controlled-devnet",
        "params": {
            "block_tx_signature_policy": "required",
            "ballot_profile_id": "controlled-testnet-aggregate-v1",
            "ballot_profile_active": True,
            "m3_civic_governance_strict": True,
        },
        "meta": {
            "helper_execution_profile": {
                "helper_mode_enabled": False,
                "helper_fast_path_enabled": False,
                "helper_timeout_ms": 5000,
                "enforce_helper_signature": True,
                "enforce_helper_certificate_consistency": True,
                "enforce_helper_tx_order_hash": True,
                "enforce_helper_namespace_hash": True,
                "enforce_helper_receipts_root": True,
            }
        },
    }


def test_checked_in_consensus_profile_manifest_is_self_hashing() -> None:
    manifest = load_consensus_profile_manifest()
    assert manifest["schema"] == "weall.consensus_profile_manifest.v1"
    assert len(manifest["manifest_hash"]) == 64


def test_mixed_consensus_projection_rejects_each_policy_dimension() -> None:
    local = consensus_activation_projection(_base_state())
    mutations = {
        "block_tx_signature_policy": "optional_local_fixture",
        "ballot_profile_id": "legacy-local-ballots",
        "ballot_profile_active": False,
        "m3_civic_governance_strict": False,
        "helper_reputation_transition_policy": "proposer_committed_v0",
        "scheduler_error_policy": "fail_open",
        "consensus_error_policy": "fail_open",
        "runtime_mode_consensus_authority": True,
    }
    for key, value in mutations.items():
        remote = copy.deepcopy(local)
        remote[key] = value
        assert consensus_profile_mismatch_reasons(local, remote) == [
            f"consensus_profile_{key}_mismatch"
        ]

    remote = copy.deepcopy(local)
    remote["helper_execution_profile"]["helper_fast_path_enabled"] = True
    assert consensus_profile_mismatch_reasons(local, remote) == [
        "consensus_profile_helper_execution_profile_mismatch"
    ]
