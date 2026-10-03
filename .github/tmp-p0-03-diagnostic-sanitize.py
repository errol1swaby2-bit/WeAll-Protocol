from __future__ import annotations

from pathlib import Path


path = Path(__file__).with_name("tmp-p0-03-follower-diagnostic.py")
text = path.read_text(encoding="utf-8")
old = '''    chain = bft_votecheck._speculative_chain_to_parent(node, b2_id)\n    print("P0DIAG_B3_PARENT_CHAIN", None if chain is None else [str(x.get("block_id") or "") for x in chain], flush=True)\n    if chain is not None:\n        trace_parent_replay(node, chain)\n'''
new = '''    chain = bft_votecheck._speculative_chain_to_parent(node, b2_id)\n    print("P0DIAG_B3_PARENT_CHAIN", None if chain is None else [str(x.get("block_id") or "") for x in chain], flush=True)\n'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"diagnostic parent subtrace: expected one match, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
