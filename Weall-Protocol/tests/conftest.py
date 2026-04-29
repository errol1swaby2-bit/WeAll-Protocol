from __future__ import annotations

import sys
from pathlib import Path

# Ensure local "src/" takes precedence over any globally-installed "weall" package.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

src_str = str(SRC)
if src_str not in sys.path:
    sys.path.insert(0, src_str)

from weall.tx.canon import ensure_tx_index_json  # noqa: E402

# Make test collection resilient on a fresh clone / first boot.
# If the generated tx index is missing or stale, rebuild it before tests import
# files that read generated/tx_index.json at module scope.
ensure_tx_index_json(
    spec_path=ROOT / "specs" / "tx_canon" / "tx_canon.yaml",
    out_path=ROOT / "generated" / "tx_index.json",
)
