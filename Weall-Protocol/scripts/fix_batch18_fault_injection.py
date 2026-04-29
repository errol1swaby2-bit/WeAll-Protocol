#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "src" / "weall" / "runtime" / "fault_injection.py"
    text = path.read_text(encoding="utf-8")

    old_import = """from weall.runtime.bft_hotstuff import (
    BftVote,
    canonical_proposal_message,
    canonical_timeout_message,
    canonical_vote_message,
    leader_for_view,
)
"""
    new_import = """from weall.runtime.bft_hotstuff import (
    BftVote,
    canonical_proposal_message,
    canonical_timeout_message,
    canonical_vote_message,
    leader_for_view,
    quorum_threshold,
)
"""
    if old_import not in text and new_import not in text:
        raise SystemExit("expected bft_hotstuff import block not found")

    if old_import in text:
        text = text.replace(old_import, new_import, 1)

    old_loop = "    for signer in list(validators)[:3]:\n"
    new_loop = """    signer_count = quorum_threshold(len(validators))
    for signer in list(validators)[:signer_count]:
"""
    if old_loop not in text and new_loop not in text:
        raise SystemExit("expected QC signer loop not found")

    if old_loop in text:
        text = text.replace(old_loop, new_loop, 1)

    path.write_text(text, encoding="utf-8")
    print(f"patched {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
