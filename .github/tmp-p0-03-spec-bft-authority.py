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
    # downgrade consensus admission while validating a production proposal.
    clone._bft_enabled_effective = bool(getattr(self, "_bft_enabled_effective", False))
    return clone
'''
text = replace_once(text, old, new, "speculative BFT authority")
votecheck.write_text(text, encoding="utf-8")


test_path = root / "tests/test_priority2_votecheck_dos_hardening.py"
text = test_path.read_text(encoding="utf-8")
append = '''\n\ndef test_speculative_executor_preserves_live_bft_authority(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    monkeypatch.setenv("WEALL_MODE", "testnet")\n    monkeypatch.setenv("WEALL_SIGVERIFY", "0")\n\n    follower = _make_executor(tmp_path, "authority-source", chain_id="votecheck-authority")\n    follower._bft_enabled_effective = True\n    slot = follower._make_spec_exec_slot()\n    clone = follower._reset_spec_exec_slot(slot)\n\n    assert clone is not follower\n    assert clone._bft_enabled_effective is True\n\n    follower._bft_enabled_effective = False\n    clone2 = follower._reset_spec_exec_slot(slot)\n    assert clone2._bft_enabled_effective is False\n'''
if "test_speculative_executor_preserves_live_bft_authority" in text:
    raise SystemExit("speculative BFT authority regression already present")
text = text.rstrip() + append + "\n"
test_path.write_text(text, encoding="utf-8")
