from __future__ import annotations

import copy
from pathlib import Path

import pytest

import weall.runtime.block_builder as block_builder
import weall.runtime.block_replay as block_replay
from weall.api import __main__ as api_main
from weall.api.routes_public_parts import state as state_routes
from weall.runtime.account_id import strict_account_ids_enabled
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import runtime_mode
from weall.runtime.system_tx_engine import enqueue_system_tx


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, chain_id: str, state: dict) -> WeAllExecutor:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    ex.state = ex._ledger_store.read()  # type: ignore[attr-defined]
    return ex


def _account_register(chain_id: str, signer: str) -> dict:
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": 1,
        "chain_id": chain_id,
        "payload": {"pubkey": f"k:{signer}"},
        "sig": "",
        "parent": None,
        "system": False,
    }


def _permissive_fixture_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)


def test_post31_001_user_replacement_cannot_satisfy_required_pre_system_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _permissive_fixture_mode(monkeypatch)
    chain_id = "post31-pre-replacement"
    state = {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {},
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
    }
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="pre",
    )
    leader = _executor(tmp_path / "leader", chain_id=chain_id, state=state)
    follower = _executor(tmp_path / "follower", chain_id=chain_id, state=state)
    add_result = leader._mempool.add(  # type: ignore[attr-defined]
        _account_register(chain_id, "@alice"), current_height=0
    )
    assert add_result["ok"] is True

    real_emit = block_builder.emit_system_txs

    def _censor_only_pre(*args, **kwargs):
        emitted = real_emit(*args, **kwargs)
        if str(kwargs.get("phase") or "").strip().lower() == "pre":
            return []
        return emitted

    monkeypatch.setattr(block_builder, "emit_system_txs", _censor_only_pre)
    block, _new_state, _applied, _invalid, err = leader.build_block_candidate(
        max_txs=1, allow_empty=True
    )
    assert err == ""
    assert isinstance(block, dict)
    assert len(block.get("txs") or []) == 1
    assert (block["txs"][0] or {}).get("system") is False

    before = copy.deepcopy(follower.state)
    result = follower.apply_block(block)

    assert result.ok is False
    assert result.error == "bad_block:required_system_pre_missing_or_reordered"
    assert follower.state == before


def test_post31_002_mandatory_post_system_work_trims_user_tail_instead_of_rejecting_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _permissive_fixture_mode(monkeypatch)
    chain_id = "post31-post-capacity"
    state = {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {
            "@operator": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 10,
            }
        },
        "roles": {
            "node_operators": {
                "by_id": {"@operator": {"account_id": "@operator", "enrolled": True}},
                "active_set": [],
            }
        },
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
    }
    leader = _executor(tmp_path / "leader", chain_id=chain_id, state=state)
    for signer in ("@alice", "@bob"):
        result = leader._mempool.add(  # type: ignore[attr-defined]
            _account_register(chain_id, signer), current_height=0
        )
        assert result["ok"] is True

    monkeypatch.setattr(block_builder, "DEFAULT_MAX_BLOCK_TXS", 2)
    monkeypatch.setattr(block_builder, "run_leader_pre_schedulers", lambda *args, **kwargs: None)

    def _post_scheduler(working: dict, *, next_height: int, scheduler_set=None) -> None:
        del scheduler_set
        enqueue_system_tx(
            working,
            tx_type="ROLE_NODE_OPERATOR_ACTIVATE",
            payload={"account_id": "@operator"},
            due_height=int(next_height),
            signer="SYSTEM",
            once=True,
            parent=None,
            phase="post",
        )

    monkeypatch.setattr(block_builder, "run_leader_post_schedulers", _post_scheduler)

    block, _new_state, _applied, _invalid, err = leader.build_block_candidate(
        max_txs=2, allow_empty=True
    )

    assert err == ""
    assert isinstance(block, dict)
    txs = list(block.get("txs") or [])
    assert len(txs) == 2
    user_txs = [tx for tx in txs if isinstance(tx, dict) and tx.get("system") is not True]
    system_txs = [tx for tx in txs if isinstance(tx, dict) and tx.get("system") is True]
    assert len(user_txs) == 1
    assert [str(tx.get("tx_type") or "") for tx in system_txs] == ["ROLE_NODE_OPERATOR_ACTIVATE"]


def test_post31_003_unset_mode_has_one_fail_safe_production_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "WEALL_MODE",
        "WEALL_UNSAFE_DEV",
        "WEALL_STRICT_ACCOUNT_ID",
        "WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE",
        "WEALL_STATE_BLOCK_PUBLIC_RAW",
        "WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)

    assert runtime_mode() == "prod"
    assert api_main._mode() == "prod"
    assert state_routes._mode() == "prod"
    assert strict_account_ids_enabled() is True
    assert state_routes._sync_request_routes_enabled() is False
    assert state_routes._state_raw_block_public() is False
    assert state_routes._state_sync_request_auth_required() is True


def test_post31_003_unsafe_dev_override_is_shared_by_all_mode_consumers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WEALL_MODE", raising=False)
    monkeypatch.delenv("WEALL_STRICT_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")

    assert runtime_mode() == "testnet"
    assert api_main._mode() == "testnet"
    assert state_routes._mode() == "testnet"
    assert strict_account_ids_enabled() is False
