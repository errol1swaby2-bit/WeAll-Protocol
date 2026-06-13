#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys

REQUIRED = {
    "nacl": "PyNaCl>=1.5",
    "pytest": "pytest>=8",
    "httpx": "httpx>=0.27",
}

missing: list[str] = []
for module_name, requirement in REQUIRED.items():
    if importlib.util.find_spec(module_name) is None:
        missing.append(requirement)

if missing:
    print("backend_test_dependencies_missing:" + ",".join(missing), file=sys.stderr)
    print("Install the backend package with test extras before running the full suite:", file=sys.stderr)
    print("  cd Weall-Protocol && python -m pip install -e '.[test]'", file=sys.stderr)
    raise SystemExit(1)

print("OK: backend test dependencies available")
