from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_local_two_frontend_rehearsal_passes_devnet_tx_global_api_before_subcommand_batch378() -> None:
    src = (ROOT / "scripts/devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")
    assert 'python3 scripts/devnet_tx.py --api "${NODE2_API}" create-account' in src
    assert 'python3 scripts/devnet_tx.py create-account \\n    --api "${NODE2_API}"' not in src
