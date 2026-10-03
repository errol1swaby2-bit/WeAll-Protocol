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
append = '''\n\ndef test_production_finalized_path_replay_is_scoped_and_cleared(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    monkeypatch.setenv("WEALL_MODE", "prod")\n    ex = _executor(tmp_path, "node-finalized", chain_id="batch98-finalized")\n\n    ex.state["tip"] = "A"\n    ex.state["height"] = 1\n    ex._bft.finalized_block_id = "B"\n    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)\n    ex._bft_parent_ready_for_apply = MethodType(lambda self, block: True, ex)\n\n    block = {\n        "block_id": "B",\n        "block_hash": "B-h",\n        "prev_block_id": "A",\n        "height": 2,\n        "header": {\n            "chain_id": "batch98-finalized",\n            "height": 2,\n            "block_ts_ms": 2,\n        },\n        "txs": [],\n    }\n    ex._pending_remote_blocks["B"] = dict(block)\n    ex._index_pending_remote_block(block)\n\n    seen: list[bool] = []\n\n    def _fake_apply_block(self: WeAllExecutor, blk: dict[str, object]) -> ExecutorMeta:\n        seen.append(bool(getattr(self, "_bft_authenticated_finalized_replay", False)))\n        self.state["tip"] = str(blk["block_id"])\n        self.state["height"] = int(blk["height"])\n        return ExecutorMeta(ok=True, height=2, block_id="B")\n\n    ex.apply_block = MethodType(_fake_apply_block, ex)\n\n    metas = ex.bft_try_apply_pending_remote_blocks()\n\n    assert len(metas) == 1\n    assert seen == [True]\n    assert str(ex.state.get("tip") or "") == "B"\n    assert getattr(ex, "_bft_authenticated_finalized_replay", False) is False\n'''
if "test_production_finalized_path_replay_is_scoped_and_cleared" in text:
    raise SystemExit("finalized replay scope regression already present")
text = text.rstrip() + append + "\n"
test_path.write_text(text, encoding="utf-8")
