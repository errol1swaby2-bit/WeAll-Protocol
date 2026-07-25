#!/usr/bin/env python3
from __future__ import annotations

# Compatibility entrypoint retained because the M3 crosswalk names this file.
# The canonical implementation lives in gen_m3_closure_manifest.py.
from gen_m3_closure_manifest import main


if __name__ == "__main__":
    raise SystemExit(main())
