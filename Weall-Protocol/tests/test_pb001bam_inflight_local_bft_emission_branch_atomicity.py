from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net import net_loop as net_loop_module
from weall.net.messages import BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _Mempool:
    def read_all(self):
        return []


class _Node:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            peer_id="local",
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        )
        self.calls: list[tuple[object, str]] = []

    def broadcast_message(self, msg, exclude_peer_id: str = "") -> int:
        self.calls.append((msg, exclude_peer_id))
        return 1


class _BranchOutboundExecutor:
    def __init__(self) -> None:
        self.generation = 0
        self.current = {
            "proposal": True,
            "vote": True,
            "timeout": True,
            "qc": True,
        }
        self.guard_calls: list[str] = []
        self.sent_marks: list[str] = []
        self.pending: list[dict] = []

    def bft_branch_generation(self) -> int:
        return int(self.generation)

    def bft_pending_outbound_messages(self):
        out = [dict(item) for item in self.pending]
        for item in out:
            self.current[str(item.get("kind") or "")] = False
        if out:
            self.generation += 1
        return out

    def bft_send_local_artifact_if_current(self, kind: str, payload: dict, send_fn) -> bool:
        del payload
        k = str(kind)
        self.guard_calls.append(k)
        if not self.current.get(k, False):
            return False
        send_fn()
        if k in {"vote", "timeout"}:
            self.sent_marks.append(k)
        return True

    def bft_mark_outbound_sent(self, kind: str, payload: dict) -> None:
        del payload
        self.sent_marks.append(str(kind))

    def bft_leader_propose(self):
        proposal = {
            "chain_id": "chain-A",
            "view": 9,
            "block_id": "branch-a-proposal",
            "block_hash": "aa" * 32,
            "prev_block_id": "branch-a-parent",
            "proposer": "@v1",
        }
        self.current["proposal"] = False
        self.generation += 1
        return proposal

    def bft_drive_timeouts(self, now_ms: int):
        del now_ms
        return None

    def bft_timeout_check(self):
        return None

    def bft_on_vote(self, payload: dict):
        del payload
        return {
            "t": "QC",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "77" * 32,
            "parent_id": "b6",
            "votes": [],
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
        }

    def bft_on_qc(self, payload: dict):
        del payload
        self.current["qc"] = False
        self.generation += 1
        return None

    def bft_artifact_dedupe_key(self, kind: str, payload: dict) -> str:
        return f"{kind}:{payload.get('view')}:{payload.get('block_id')}"

    def bft_artifact_was_accepted(self, kind: str, payload: dict) -> bool:
        del payload
        return str(kind) == "vote"

    def bft_current_view(self) -> int:
        return 7

    def bft_current_validator_epoch(self) -> int:
        return 2

    def bft_current_validator_set_hash(self) -> str:
        return "set-2"


def _loop(executor: _BranchOutboundExecutor) -> NetMeshLoop:
    loop = NetMeshLoop(
        executor=executor,
        mempool=_Mempool(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop.node = _Node()
    loop._bft_enabled = True
    loop._relay_client_enabled = False
    loop._bft_propose_interval_ms = 10**18
    loop._bft_vote_interval_ms = 10**18
    loop._bft_timeout_interval_ms = 10**18
    now = net_loop_module._now_ms()
    loop._last_bft_propose_ms = now
    loop._last_bft_vote_ms = now
    loop._last_bft_timeout_ms = now
    return loop


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        (
            "vote",
            {
                "t": "VOTE",
                "chain_id": "chain-A",
                "view": 7,
                "block_id": "b7",
                "block_hash": "77" * 32,
                "parent_id": "b6",
                "signer": "@v1",
            },
        ),
        (
            "timeout",
            {
                "t": "TIMEOUT",
                "chain_id": "chain-A",
                "view": 7,
                "high_qc_id": "b6",
                "signer": "@v1",
            },
        ),
    ],
)
def test_fetched_signed_outbox_item_is_not_broadcast_after_branch_reset(
    kind: str,
    payload: dict,
) -> None:
    ex = _BranchOutboundExecutor()
    ex.pending = [{"kind": kind, "payload": dict(payload)}]
    loop = _loop(ex)

    loop._outbound_bft_tick()

    assert loop.node.calls == []
    assert ex.guard_calls == [kind]
    assert ex.sent_marks == []


def test_locally_signed_proposal_is_not_broadcast_after_branch_reset() -> None:
    ex = _BranchOutboundExecutor()
    loop = _loop(ex)
    loop._bft_propose_interval_ms = 1
    loop._last_bft_propose_ms = 0

    loop._outbound_bft_tick()

    assert loop.node.calls == []
    assert ex.guard_calls == ["proposal"]


def test_locally_formed_qc_is_not_broadcast_after_branch_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = _BranchOutboundExecutor()
    loop = _loop(ex)

    monkeypatch.setattr(loop, "_bft_payload_reject_reason", lambda *_a, **_k: None)
    monkeypatch.setattr(loop, "_bft_prefilter_reject_reason", lambda *_a, **_k: (None, {}))
    monkeypatch.setattr("weall.net.net_loop._cheap_validate_bft_payload", lambda *_a, **_k: None)

    msg = BftVoteMsg(
        header=WireHeader(
            type=MsgType.BFT_VOTE,
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="deadbeef",
        ),
        view=7,
        vote={
            "t": "VOTE",
            "chain_id": "chain-A",
            "view": 7,
            "block_id": "b7",
            "block_hash": "77" * 32,
            "parent_id": "b6",
            "signer": "@v2",
            "pubkey": "pub",
            "sig": "sig",
            "validator_epoch": 2,
            "validator_set_hash": "set-2",
            "consensus_phase": "bft_active",
        },
    )

    assert loop._on_bft_vote("peer-a", msg) is True

    assert loop.node.calls == []
    assert "qc" in ex.guard_calls
