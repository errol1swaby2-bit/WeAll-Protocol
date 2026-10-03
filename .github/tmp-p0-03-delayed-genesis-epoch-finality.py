from __future__ import annotations

from pathlib import Path


repo = Path(__file__).resolve().parents[1]
source = repo / "Weall-Protocol/src/weall/runtime/apply/consensus.py"
text = source.read_text(encoding="utf-8")
old = '''    if int(height) == 1:
        enqueue_system_tx(
            state,
            tx_type="EPOCH_OPEN",
            payload={"epoch": 1},
            due_height=max(2, _as_int(state.get("height"), 0) + 1),
            phase="post",
        )
'''
new = '''    if int(height) == 1:
        # HotStuff finality may arrive after the validator/consensus lifecycle
        # has already established epoch 1.  In that case replaying the delayed
        # height-one finality receipt must not enqueue a stale EPOCH_OPEN(1),
        # which would violate the sequential epoch transition contract.
        consensus = _ensure_consensus(state)
        epochs = consensus.get("epochs") if isinstance(consensus.get("epochs"), dict) else {}
        if _as_int(epochs.get("current"), 0) <= 0:
            enqueue_system_tx(
                state,
                tx_type="EPOCH_OPEN",
                payload={"epoch": 1},
                due_height=max(2, _as_int(state.get("height"), 0) + 1),
                phase="post",
            )
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"delayed height-one epoch-open replacement count={count}")
source.write_text(text.replace(old, new, 1), encoding="utf-8")
