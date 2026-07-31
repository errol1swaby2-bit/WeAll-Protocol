from __future__ import annotations

from weall.runtime.protocol_profile import (
    BLOCK_TX_SIGNATURE_POLICY_LOCAL_FIXTURE,
    BLOCK_TX_SIGNATURE_POLICY_REQUIRED,
    block_tx_signature_policy,
    block_tx_signatures_required,
)


def test_canonical_chain_signature_policy_is_mode_independent(monkeypatch) -> None:
    state = {"chain_id": "weall-controlled-devnet", "params": {}}

    monkeypatch.setenv("WEALL_MODE", "dev")
    dev_policy = block_tx_signature_policy(state)
    dev_required = block_tx_signatures_required(state)

    monkeypatch.setenv("WEALL_MODE", "prod")
    prod_policy = block_tx_signature_policy(state)
    prod_required = block_tx_signatures_required(state)

    assert dev_policy == prod_policy == BLOCK_TX_SIGNATURE_POLICY_REQUIRED
    assert dev_required is prod_required is True


def test_root_committed_signature_policy_overrides_process_mode(monkeypatch) -> None:
    state = {
        "chain_id": "fixture-chain",
        "params": {"block_tx_signature_policy": BLOCK_TX_SIGNATURE_POLICY_REQUIRED},
    }
    for mode in ("dev", "testnet", "prod"):
        monkeypatch.setenv("WEALL_MODE", mode)
        assert block_tx_signatures_required(state) is True


def test_noncanonical_unsigned_policy_is_explicit_local_fixture_compatibility(monkeypatch) -> None:
    state = {"chain_id": "fixture-chain", "params": {}}
    for mode in ("dev", "prod"):
        monkeypatch.setenv("WEALL_MODE", mode)
        assert block_tx_signature_policy(state) == BLOCK_TX_SIGNATURE_POLICY_LOCAL_FIXTURE
        assert block_tx_signatures_required(state) is False
