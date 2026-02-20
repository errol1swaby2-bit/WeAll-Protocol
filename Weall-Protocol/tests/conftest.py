from __future__ import annotations

import sys
from pathlib import Path

# Ensure local "src/" takes precedence over any globally-installed "weall" package.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

src_str = str(SRC)
if src_str not in sys.path:
    sys.path.insert(0, src_str)
