from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1] / "Weall-Protocol"

# A block that is already on the HotStuff finalized replay path has crossed the
# consensus authorization boundary. Durable replay still validates every normal
# block/transaction/root invariant, but it must not be rejected merely because a
# newer local HotStuff lock now points at one of its descendants.
block_replay = root / "src/weall/runtime/block_replay.py"
text = block_replay.read_text(encoding="utf-8")
old = '''    if effective_bft_enabled(executor=self, default=False) and not bool(
        getattr(self, "_speculative_authenticated_ancestor_replay", False)
    ):
'''
new = '''    if (
        effective_bft_enabled(executor=self, default=False)
        and not bool(getattr(self, "_speculative_authenticated_ancestor_replay", False))
        and not bool(getattr(self, "_bft_authenticated_finalized_replay", False))
    ):
'''
text = replace_once(text, old, new, "finalized replay commit-admission scope")
block_replay.write_text(text, encoding="utf-8")


frontier = root / "src/weall/runtime/bft_pending_frontier_impl.py"
text = frontier.read_text(encoding="utf-8")
old = '''            if existing_justify is None:
                if qc_is_parent_justify:
                    blk2["justify_qc"] = dict(qcj)
                elif qc_is_self_commit and synthetic_replay:
                    blk2["justify_qc"] = dict(qcj)
            else:
                existing_bid = str(existing_justify.get("block_id") or "").strip()
                existing_bh = str(existing_justify.get("block_hash") or "").strip()
                if (existing_bid and qc_bid and existing_bid != qc_bid) or (
                    existing_bh and qc_bh and existing_bh != qc_bh
                ):
                    self._drop_pending_candidate_artifacts(bid)
                    made_progress = True
                    continue
            if qc_is_self_commit and not synthetic_replay:
                blk2["qc"] = dict(qcj)
'''
new = '''            if existing_justify is None:
                if qc_is_parent_justify:
                    blk2["justify_qc"] = dict(qcj)
                elif qc_is_self_commit and synthetic_replay:
                    blk2["justify_qc"] = dict(qcj)
            elif qc_is_parent_justify:
                existing_bid = str(existing_justify.get("block_id") or "").strip()
                existing_bh = str(existing_justify.get("block_hash") or "").strip()
                if (existing_bid and qc_bid and existing_bid != qc_bid) or (
                    existing_bh and qc_bh and existing_bh != qc_bh
                ):
                    self._drop_pending_candidate_artifacts(bid)
                    made_progress = True
                    continue
            elif not qc_is_self_commit:
                # A cached certificate that is neither this block's commit QC nor
                # its parent justification has no valid replay role. Fail closed
                # rather than rewriting the block's certified ancestry.
                self._drop_pending_candidate_artifacts(bid)
                made_progress = True
                continue
            if qc_is_self_commit and not synthetic_replay:
                # The block's self-commit QC is distinct from the parent QC already
                # carried in justify_qc. Preserve both domains independently.
                blk2["qc"] = dict(qcj)
'''
text = replace_once(text, old, new, "self-commit versus parent-justify QC replay")

old = '''        meta = self.apply_block(blk2)
        applied += 1
'''
new = '''        authorized_finalized_replay = bool(
            _mode() == "prod"
            and finalized_replay_path is not None
            and bid in finalized_replay_path
        )
        prior_finalized_replay = bool(
            getattr(self, "_bft_authenticated_finalized_replay", False)
        )
        if authorized_finalized_replay:
            self._bft_authenticated_finalized_replay = True
        try:
            meta = self.apply_block(blk2)
        finally:
            self._bft_authenticated_finalized_replay = prior_finalized_replay
        applied += 1
'''
text = replace_once(text, old, new, "finalized path replay marker")
frontier.write_text(text, encoding="utf-8")


test_path = root / "tests/test_priority1_pending_frontier_apply_order.py"
text = test_path.read_text(encoding="utf-8")
old = '''def test_pending_frontier_drops_conflicting_cached_qc_when_block_already_has_justify_qc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _executor(tmp_path, "node-b", chain_id="batch98-b")

    bid = "B"
    block = {
        "block_id": bid,
        "block_hash": "B-h",
        "prev_block_id": "A",
        "height": 2,
        "justify_qc": {
            "chain_id": "batch98-b",
            "view": 5,
            "block_id": "A",
            "block_hash": "A-h",
            "parent_id": "genesis",
            "votes": [],
        },
        "header": {"chain_id": "batch98-b", "height": 2, "block_ts_ms": 2},
        "txs": [],
    }
    conflicting_qcj = {
        "chain_id": "batch98-b",
        "view": 7,
        "block_id": bid,
        "block_hash": "B-h",
        "parent_id": "A",
        "votes": [],
    }

    ex.state["tip"] = "A"
    ex.state["height"] = 1
    ex._pending_remote_blocks[bid] = dict(block)
    ex._index_pending_remote_block(block)
    ex._put_pending_missing_qc(conflicting_qcj)

    called = {"apply": 0}

    def _fake_apply_block(self: WeAllExecutor, blk: dict[str, object]) -> ExecutorMeta:
        called["apply"] += 1
        return ExecutorMeta(ok=True, height=2, block_id=bid)

    ex.apply_block = MethodType(_fake_apply_block, ex)

    metas = ex.bft_try_apply_pending_remote_blocks()

    assert metas == []
    assert called["apply"] == 0
    assert bid not in ex._pending_remote_blocks
    assert ex._pending_missing_qc_json(block_id=bid) is None
'''
new = '''def test_pending_frontier_preserves_parent_justify_when_cached_qc_is_self_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _executor(tmp_path, "node-b", chain_id="batch98-b")

    bid = "B"
    block = {
        "block_id": bid,
        "block_hash": "B-h",
        "prev_block_id": "A",
        "height": 2,
        "validator_epoch": 1,
        "validator_set_hash": "set-h",
        "justify_qc": {
            "chain_id": "batch98-b",
            "view": 5,
            "block_id": "A",
            "block_hash": "A-h",
            "parent_id": "genesis",
            "votes": [],
        },
        "header": {"chain_id": "batch98-b", "height": 2, "block_ts_ms": 2},
        "txs": [],
    }
    self_commit_qcj = {
        "chain_id": "batch98-b",
        "view": 7,
        "block_id": bid,
        "block_hash": "B-h",
        "parent_id": "A",
        "votes": [],
    }

    ex.state["tip"] = "A"
    ex.state["height"] = 1
    ex._pending_remote_blocks[bid] = dict(block)
    ex._index_pending_remote_block(block)
    ex._put_pending_missing_qc(self_commit_qcj)

    seen: list[dict[str, object]] = []

    def _fake_apply_block(self: WeAllExecutor, blk: dict[str, object]) -> ExecutorMeta:
        seen.append(dict(blk))
        return ExecutorMeta(ok=True, height=2, block_id=bid)

    ex.apply_block = MethodType(_fake_apply_block, ex)

    metas = ex.bft_try_apply_pending_remote_blocks()

    assert len(metas) == 1
    assert len(seen) == 1
    assert isinstance(seen[0].get("justify_qc"), dict)
    assert seen[0]["justify_qc"]["block_id"] == "A"
    assert isinstance(seen[0].get("qc"), dict)
    assert seen[0]["qc"]["block_id"] == bid
'''
text = replace_once(text, old, new, "self-commit QC replay regression")

append = '''\n\ndef test_production_finalized_path_replay_is_scoped_and_cleared(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    monkeypatch.setenv("WEALL_MODE", "prod")\n    ex = _executor(tmp_path, "node-finalized", chain_id="batch98-finalized")\n\n    ex.state["tip"] = "A"\n    ex.state["height"] = 1\n    ex._bft.finalized_block_id = "B"\n    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)\n    ex._bft_parent_ready_for_apply = MethodType(lambda self, block: True, ex)\n\n    block = {\n        "block_id": "B",\n        "block_hash": "B-h",\n        "prev_block_id": "A",\n        "height": 2,\n        "header": {\n            "chain_id": "batch98-finalized",\n            "height": 2,\n            "block_ts_ms": 2,\n        },\n        "txs": [],\n    }\n    ex._pending_remote_blocks["B"] = dict(block)\n    ex._index_pending_remote_block(block)\n\n    seen: list[bool] = []\n\n    def _fake_apply_block(self: WeAllExecutor, blk: dict[str, object]) -> ExecutorMeta:\n        seen.append(bool(getattr(self, "_bft_authenticated_finalized_replay", False)))\n        self.state["tip"] = str(blk["block_id"])\n        self.state["height"] = int(blk["height"])\n        return ExecutorMeta(ok=True, height=2, block_id="B")\n\n    ex.apply_block = MethodType(_fake_apply_block, ex)\n\n    metas = ex.bft_try_apply_pending_remote_blocks()\n\n    assert len(metas) == 1\n    assert seen == [True]\n    assert str(ex.state.get("tip") or "") == "B"\n    assert getattr(ex, "_bft_authenticated_finalized_replay", False) is False\n'''
if "test_production_finalized_path_replay_is_scoped_and_cleared" in text:
    raise SystemExit("finalized replay scope regression already present")
text = text.rstrip() + append + "\n"
test_path.write_text(text, encoding="utf-8")
