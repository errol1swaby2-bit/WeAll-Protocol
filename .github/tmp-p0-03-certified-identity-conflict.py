from __future__ import annotations

from pathlib import Path


repo = Path(__file__).resolve().parents[1]
source = repo / "Weall-Protocol/src/weall/runtime/bft_pending_frontier_impl.py"
text = source.read_text(encoding="utf-8")
anchor = '''def _block_identity_conflicts(self, block: Json, *, record_conflicts: bool = True) -> bool:
'''
helper = '''def _verified_qc_pins_block_identity(self, *, block_id: str, block_hash: str) -> bool:
    bid = str(block_id or "").strip()
    bh = str(block_hash or "").strip()
    if not bid or not bh:
        return False

    bft = getattr(self, "_bft", None)
    for attr in ("high_qc", "locked_qc", "validator_transition_qc"):
        qc = getattr(bft, attr, None) if bft is not None else None
        if qc is None:
            continue
        if (
            str(getattr(qc, "block_id", "") or "").strip() == bid
            and str(getattr(qc, "block_hash", "") or "").strip() == bh
        ):
            return True

    qcj = self._pending_missing_qc_json(block_id=bid)
    verifier = getattr(self, "bft_verify_qc_json", None)
    if not isinstance(qcj, dict) or not callable(verifier):
        return False
    try:
        verified = verifier(dict(qcj))
    except Exception:
        return False
    return bool(
        verified is not None
        and str(getattr(verified, "block_id", "") or "").strip() == bid
        and str(getattr(verified, "block_hash", "") or "").strip() == bh
    )


def _block_identity_conflicts(self, block: Json, *, record_conflicts: bool = True) -> bool:
'''
if text.count(anchor) != 1:
    raise SystemExit(f"certified identity helper anchor count={text.count(anchor)}")
text = text.replace(anchor, helper, 1)

old = '''        if record_conflicts:
            self._mark_block_id_conflict(
                block_id=bid,
                known_hash=known,
                new_hash=block_hash,
                source="block",
                parent_id=str(block.get("prev_block_id") or ""),
            )
        return True
'''
new = '''        # A verified QC pins the already-known (block_id, block_hash) identity.
        # A later signed alternate may be rejected as equivocation, but it must
        # not revoke the certified identity or delete the certified pending parent.
        if _verified_qc_pins_block_identity(self, block_id=bid, block_hash=known):
            if record_conflicts:
                self._bft_record_event(
                    "bft_certified_block_identity_conflict_rejected",
                    block_id=bid,
                    certified_block_hash=known,
                    rejected_block_hash=block_hash,
                    parent_id=str(block.get("prev_block_id") or "").strip(),
                )
            return True
        if record_conflicts:
            self._mark_block_id_conflict(
                block_id=bid,
                known_hash=known,
                new_hash=block_hash,
                source="block",
                parent_id=str(block.get("prev_block_id") or ""),
            )
        return True
'''
if text.count(old) != 1:
    raise SystemExit(f"certified identity conflict replacement count={text.count(old)}")
source.write_text(text.replace(old, new, 1), encoding="utf-8")

test = repo / "Weall-Protocol/tests/test_p0_03_production_composition.py"
text = test.read_text(encoding="utf-8")
old_test = '''    with _env(_prod_env(victim, pub=pubs[victim], priv=privs[victim])):
        assert nodes[victim].bft_on_proposal(copy.deepcopy(wrong)) is None

    votes2 = _follower_votes(nodes, b2, leader=leader2, pubs=pubs, privs=privs)
'''
new_test = '''    with _env(_prod_env(victim, pub=pubs[victim], priv=privs[victim])):
        assert nodes[victim].bft_on_proposal(copy.deepcopy(wrong)) is None
    b1_id = str(b1["block_id"])
    assert nodes[victim]._is_conflicted_block_id(b1_id) is False
    assert b1_id in nodes[victim]._bft_speculative_blocks_map()

    votes2 = _follower_votes(nodes, b2, leader=leader2, pubs=pubs, privs=privs)
'''
if text.count(old_test) != 1:
    raise SystemExit(f"certified identity regression insertion count={text.count(old_test)}")
test.write_text(text.replace(old_test, new_test, 1), encoding="utf-8")
