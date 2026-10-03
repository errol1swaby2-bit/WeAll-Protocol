from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1] / "Weall-Protocol"

votecheck = root / "src/weall/runtime/bft_votecheck.py"
text = votecheck.read_text(encoding="utf-8")
old = '''    return WeAllExecutor(
        db_path=str(db_path),
        aux_db_path=str(aux_path),
        node_id=str(self.node_id),
        chain_id=str(self.chain_id),
        tx_index_path=str(self.tx_index_path),
    )
'''
new = '''    clone = WeAllExecutor(
        db_path=str(db_path),
        aux_db_path=str(aux_path),
        node_id=str(self.node_id),
        chain_id=str(self.chain_id),
        tx_index_path=str(self.tx_index_path),
    )
    # This executor is an ephemeral replay surface for the live node, not an
    # independently bootstrapped node. Its startup state is intentionally empty,
    # so lifecycle evaluation at construction time can differ from the source
    # node until the speculative parent state is loaded. Preserve the source
    # node's already-resolved BFT authority posture so replay cannot silently
    # downgrade consensus semantics while validating a production proposal.
    clone._bft_enabled_effective = bool(getattr(self, "_bft_enabled_effective", False))
    return clone
'''
text = replace_once(text, old, new, "speculative BFT authority")

old = '''    clone.state = copy.deepcopy(self.state)
    clone._ledger_store.write(clone.state)
    clone._bft.load_from_state(clone.state)
    for pending in chain:
        meta = clone.apply_block(copy.deepcopy(pending))
        if meta is None or not bool(getattr(meta, "ok", False)):
            return False
    return str(clone.state.get("tip") or "").strip() == target
'''
new = '''    clone.state = copy.deepcopy(self.state)
    clone._ledger_store.write(clone.state)
    clone._bft.load_from_state(clone.state)
    # These blocks came only from the authenticated pending frontier selected by
    # ``_speculative_chain_to_parent``. They were already admitted when received
    # and may now sit behind a newer HotStuff lock. Reconstruct their deterministic
    # state effects (including BFT finality scheduling) without re-running the
    # *current* lock/finalized-path commit gate against historical ancestors.
    # The marker is private to this ephemeral clone and is cleared before the new
    # candidate is replayed, so candidate admission remains fully fail-closed.
    prior_ancestor_replay = bool(
        getattr(clone, "_speculative_authenticated_ancestor_replay", False)
    )
    clone._speculative_authenticated_ancestor_replay = True
    try:
        for pending in chain:
            meta = clone.apply_block(copy.deepcopy(pending))
            if meta is None or not bool(getattr(meta, "ok", False)):
                return False
    finally:
        clone._speculative_authenticated_ancestor_replay = prior_ancestor_replay
    return str(clone.state.get("tip") or "").strip() == target
'''
text = replace_once(text, old, new, "certified ancestor replay scope")
votecheck.write_text(text, encoding="utf-8")


block_replay = root / "src/weall/runtime/block_replay.py"
text = block_replay.read_text(encoding="utf-8")
old = '''    if effective_bft_enabled(executor=self, default=False):
        strict_bft_apply = (
'''
new = '''    if effective_bft_enabled(executor=self, default=False) and not bool(
        getattr(self, "_speculative_authenticated_ancestor_replay", False)
    ):
        strict_bft_apply = (
'''
text = replace_once(text, old, new, "certified ancestor commit-admission scope")
block_replay.write_text(text, encoding="utf-8")


test_path = root / "tests/test_priority2_votecheck_dos_hardening.py"
text = test_path.read_text(encoding="utf-8")
append = '''\n\ndef test_speculative_executor_preserves_live_bft_authority(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    monkeypatch.setenv("WEALL_MODE", "testnet")\n    monkeypatch.setenv("WEALL_SIGVERIFY", "0")\n\n    follower = _make_executor(tmp_path, "authority-source", chain_id="votecheck-authority")\n    follower._bft_enabled_effective = True\n    slot = follower._make_spec_exec_slot()\n    clone = follower._reset_spec_exec_slot(slot)\n\n    assert clone is not follower\n    assert clone._bft_enabled_effective is True\n    assert getattr(clone, "_speculative_authenticated_ancestor_replay", False) is False\n\n    follower._bft_enabled_effective = False\n    clone2 = follower._reset_spec_exec_slot(slot)\n    assert clone2._bft_enabled_effective is False\n'''
if "test_speculative_executor_preserves_live_bft_authority" in text:
    raise SystemExit("speculative BFT authority regression already present")
text = text.rstrip() + append + "\n"
test_path.write_text(text, encoding="utf-8")
