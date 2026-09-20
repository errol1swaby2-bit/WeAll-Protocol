from __future__ import annotations

import copy
from pathlib import Path

import pytest

import weall.runtime.block_builder as block_builder
import weall.runtime.block_replay as block_replay
import weall.runtime.executor as executor_mod
from weall.runtime.errors import ApplyError
from weall.runtime.executor import WeAllExecutor
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


def _epoch_state(*, chain_id: str, epoch: int, phase: str) -> dict:
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
        payload={"epoch": int(epoch)},
        due_height=1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase=phase,
    )
    return state


@pytest.mark.parametrize("phase", ["pre", "post"])
def test_leader_aborts_candidate_when_due_system_apply_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    state = _epoch_state(chain_id=f"system-apply-fail-{phase}", epoch=99, phase=phase)
    leader = _executor(tmp_path / phase, chain_id=state["chain_id"], state=state)
    before = copy.deepcopy(leader.state)

    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    # This regression isolates mandatory SYSTEM apply failure handling. PB-001B-D
    # independently covers EPOCH_* SINGLE_TX lineage, so bypass that earlier gate
    # here to keep exercising the downstream epoch payload failure contract.
    monkeypatch.setattr(
        block_builder,
        "validate_same_block_single_tx_lineage",
        lambda *args, **kwargs: (True, ""),
    )

    block, new_state, applied, invalid, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
    )

    assert block is None
    assert new_state is None
    assert applied == []
    assert invalid == []
    assert err == (
        f"system_tx_apply_{phase}_failed:invalid_payload:epoch_open_must_advance_sequentially"
    )
    assert leader.state == before
    assert leader.state["system_queue"][0].get("emitted_height") is None


def test_follower_rejects_system_apply_failure_without_state_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _epoch_state(chain_id="system-replay-apply-fail", epoch=1, phase="pre")
    leader = _executor(tmp_path / "leader", chain_id=state["chain_id"], state=state)
    follower = _executor(tmp_path / "follower", chain_id=state["chain_id"], state=state)

    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)
    # Keep this test focused on replay apply atomicity. Canonical lineage and
    # queue-binding failures are covered by the PB-001B-D finality regressions.
    monkeypatch.setattr(
        block_builder,
        "validate_same_block_single_tx_lineage",
        lambda *args, **kwargs: (True, ""),
    )
    monkeypatch.setattr(
        block_replay,
        "validate_same_block_single_tx_lineage",
        lambda *args, **kwargs: (True, ""),
    )
    monkeypatch.setattr(
        block_replay,
        "validate_system_tx_queue_binding",
        lambda *args, **kwargs: (True, ""),
    )

    block, new_state, applied, invalid, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    assert applied
    assert invalid == []

    real_apply = executor_mod.apply_tx_atomic_meta

    def _fail_system_apply(state_obj, env, *, consume_nonce_on_fail=False):
        if bool(getattr(env, "system", False)):
            raise ApplyError(
                "invalid_payload",
                "forced_system_apply_failure",
                {"tx_type": str(getattr(env, "tx_type", "") or "")},
            )
        return real_apply(
            state_obj,
            env,
            consume_nonce_on_fail=consume_nonce_on_fail,
        )

    monkeypatch.setattr(executor_mod, "apply_tx_atomic_meta", _fail_system_apply)
    before = copy.deepcopy(follower.state)

    result = follower.apply_block(block)

    assert result.ok is False
    assert (
        result.error
        == "bad_block:system_tx_apply_failed:invalid_payload:forced_system_apply_failure"
    )
    assert follower.state == before
    assert follower.state["system_queue"][0].get("emitted_height") is None
