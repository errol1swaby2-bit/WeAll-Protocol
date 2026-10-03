from __future__ import annotations

from pathlib import Path


path = Path(__file__).resolve().parents[1] / "Weall-Protocol/src/weall/runtime/block_replay.py"
text = path.read_text(encoding="utf-8")
old = '''        if strict_bft_apply:
            ok_bft, rej_bft = _call_admit_bft_commit_block(
                block=block2,
                state=self.state,
                blocks_map=self._bft_speculative_blocks_map(),
                bft_enabled=effective_bft_enabled(executor=self, default=False),
            )
'''
new = '''        if strict_bft_apply:
            admission_blocks_map = self._bft_speculative_blocks_map()
            current_bid = str(block2.get("block_id") or "").strip()
            if current_bid:
                admission_blocks_map = dict(admission_blocks_map)
                admission_blocks_map[current_bid] = {
                    "height": int(height),
                    "prev_block_id": advertised_prev_block_id,
                    "block_ts_ms": int(ts_ms),
                    "block_hash": str(block2.get("block_hash") or "").strip(),
                }
            ok_bft, rej_bft = _call_admit_bft_commit_block(
                block=block2,
                state=self.state,
                blocks_map=admission_blocks_map,
                bft_enabled=effective_bft_enabled(executor=self, default=False),
            )
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"block replay current-candidate ancestry: expected one match, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
