from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# POST31-001 is a pre-phase completeness defect. Keep the new unconditional
# expected-pre-prefix equality, but restore the established post-phase validation
# order so malformed/unknown SYSTEM queue IDs continue to fail at the more precise
# queue-binding contract before the later post completeness comparison.
replace_once(
    "src/weall/runtime/block_replay.py",
    '''    def _queue_item_phase(queue_id: str) -> str:\n''',
    '''    def _all_queue_ids_known(queue_ids: list[str]) -> bool:\n        lookup = _queue_lookup()\n        return all(bool(qid) and qid in lookup for qid in queue_ids)\n\n    def _queue_item_phase(queue_id: str) -> str:\n''',
)

replace_once(
    "src/weall/runtime/block_replay.py",
    '''        if actual_post_queue_ids != expected_post_queue_ids:\n            return ExecutorMeta(\n                ok=False,\n                error="bad_block:required_system_post_missing_duplicated_or_reordered",\n                height=0,\n                block_id=str(block2.get("block_id") or ""),\n            )\n''',
    '''        if actual_post_queue_ids != expected_post_queue_ids:\n            try:\n                all_known = _all_queue_ids_known(actual_post_queue_ids)\n            except Exception as exc:\n                return ExecutorMeta(\n                    ok=False,\n                    error=f"bad_block:system_queue_validation_failed:{type(exc).__name__}",\n                    height=0,\n                    block_id=str(block2.get("block_id") or ""),\n                )\n            if all_known:\n                return ExecutorMeta(\n                    ok=False,\n                    error="bad_block:required_system_post_missing_duplicated_or_reordered",\n                    height=0,\n                    block_id=str(block2.get("block_id") or ""),\n                )\n''',
)

# Keep closure documentation exact to the final patch rather than claiming that
# the post-phase comparison changed its rejection precedence.
replace_once(
    "scripts/pr32_closure_builder.py",
    '"POST31-001": "mandatory SYSTEM phase completeness equality",',
    '"POST31-001": "mandatory pre-SYSTEM prefix completeness equality",',
)
replace_once(
    "scripts/pr32_closure_builder.py",
    "Follower replay now requires exact equality between the independently reconstructed mandatory SYSTEM queue-ID sequence and the received phase sequence. A user transaction, empty queue ID, unknown queue ID, omission, duplication, or reordering cannot satisfy the pre/post completeness boundary. Rejected candidates do not mutate the committed follower state.",
    "Follower replay now requires exact equality between the independently reconstructed mandatory pre-SYSTEM queue-ID sequence and the received pre-phase prefix. A user transaction, empty queue ID, unknown queue ID, omission, duplication, or reordering cannot satisfy that prefix boundary. Existing post-phase queue-binding and completeness checks remain in their established rejection order. Rejected candidates do not mutate the committed follower state.",
)
