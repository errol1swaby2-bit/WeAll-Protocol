from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = str(ROOT / "generated" / "tx_index.json")


def _set_observer_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "observer_onboarding")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.delenv("WEALL_ALLOW_EXPLICIT_VALIDATOR_SIGNING_OVERRIDE", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)


def _set_genesis_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")


def _submit_ok(ex: WeAllExecutor, tx: dict) -> str:
    result = ex.submit_tx(tx)
    assert result["ok"] is True, result
    return str(result["tx_id"])


def test_two_process_external_observer_onboarding_to_genesis_batch319(tmp_path: Path, monkeypatch) -> None:
    """Simulate the controlled external observer journey with two local executors.

    The observer executor represents Machine B and must remain non-authoritative.
    The genesis executor represents Machine A and commits observer-submitted
    onboarding transactions.  This test intentionally uses direct executor
    submission rather than HTTP so it can run fast in the normal unit suite while
    still proving the consensus-side state transition and observer posture.
    """

    # Machine B: observer process, no local block authority.
    _set_observer_env(monkeypatch)
    observer = WeAllExecutor(
        db_path=str(tmp_path / "observer.db"),
        node_id="observer-node",
        chain_id="weall-prod-rehearsal",
        tx_index_path=TX_INDEX,
    )
    assert observer.observer_mode() is True
    assert observer._validator_signing_permitted() is False
    refused = observer.produce_block(allow_empty=True)
    assert refused.ok is False
    assert refused.error.startswith("block_production_forbidden:")

    # Machine A: genesis/bootstrap process that accepts signed observer-origin
    # onboarding transactions and commits them into chain state.
    _set_genesis_env(monkeypatch)
    genesis = WeAllExecutor(
        db_path=str(tmp_path / "genesis.db"),
        node_id="genesis-node",
        chain_id="weall-prod-rehearsal",
        tx_index_path=TX_INDEX,
    )

    tx_ids: list[str] = []
    tx_ids.append(
        _submit_ok(
            genesis,
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@observer",
                "nonce": 1,
                "payload": {"pubkey": "observer-account-pubkey"},
            },
        )
    )
    assert genesis.produce_block(max_txs=1).ok is True

    observer_node_pubkey = "observer-node-pubkey"
    observer_device_id = "node:@observer:observer-node"

    tx_ids.append(
        _submit_ok(
            genesis,
            {
                "tx_type": "ACCOUNT_DEVICE_REGISTER",
                "signer": "@observer",
                "nonce": 2,
                "payload": {
                    "device_id": observer_device_id,
                    "device_type": "node",
                    "label": "Observer node",
                    "pubkey": observer_node_pubkey,
                },
            },
        )
    )
    assert genesis.produce_block(max_txs=1).ok is True

    tx_ids.append(
        _submit_ok(
            genesis,
            {
                "tx_type": "PEER_ADVERTISE",
                "signer": "@observer",
                "nonce": 3,
                "payload": {
                    "peer_id": observer_device_id,
                    "device_id": observer_device_id,
                    "node_pubkey": observer_node_pubkey,
                    "endpoint": "https://observer.example.test",
                },
            },
        )
    )
    assert genesis.produce_block(max_txs=1).ok is True

    tx_ids.append(
        _submit_ok(
            genesis,
            {
                "tx_type": "PEER_REQUEST_CONNECT",
                "signer": "@observer",
                "nonce": 4,
                "payload": {
                    "peer_id": "genesis-node",
                    "endpoint": "https://genesis.example.test",
                },
            },
        )
    )
    assert genesis.produce_block(max_txs=1).ok is True

    tx_ids.append(
        _submit_ok(
            genesis,
            {
                "tx_type": "POH_ASYNC_REQUEST_OPEN",
                "signer": "@observer",
                "nonce": 5,
                "payload": {
                    "account_id": "@observer",
                    "case_id": "pohasync:observer:1",
                    "challenge_id": "prompt:observer:1",
                    "challenge_commitment": "commit:observer:challenge:1",
                    "response_commitment": "commit:observer:response:1",
                },
            },
        )
    )

    committed = genesis.produce_block(max_txs=10)
    assert committed.ok is True
    assert committed.applied_count == 1

    state = genesis.read_state()
    assert "@observer" in state["accounts"]
    assert state["accounts"]["@observer"]["poh_tier"] == 0
    assert state["peers"]["ads"]["@observer"]["peer_id"] == observer_device_id
    assert state["peers"]["ads"]["@observer"]["node_pubkey"] == observer_node_pubkey
    assert state["peers"]["connect_requests"][0]["to_peer_id"] == "genesis-node"
    async_cases = state["poh"]["async_cases"]
    assert "pohasync:observer:1" in async_cases
    assert async_cases["pohasync:observer:1"]["account_id"] == "@observer"
    assert async_cases["pohasync:observer:1"]["status"] == "open"

    for tx_id in tx_ids:
        status = genesis.get_tx_status(tx_id)
        assert status["ok"] is True
        assert status["status"] == "confirmed"
