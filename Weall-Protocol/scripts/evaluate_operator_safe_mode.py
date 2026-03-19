#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.operator_safe_mode import safe_mode_gate  # noqa: E402


def _load_json(path_str: str):
    path = Path(path_str).resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate operator safe-mode state from incident report and optional actions.")
    parser.add_argument("report", help="Path to operator incident report JSON")
    parser.add_argument("--actions", default=None, help="Optional path to incident action JSON")
    parser.add_argument("--out", default=None, help="Optional output path")
    args = parser.parse_args()

    report = _load_json(args.report)
    actions = _load_json(args.actions) if args.actions else None
    result = safe_mode_gate(report=report, actions=actions)
    rendered = json.dumps(result, indent=2, sort_keys=True)

    if args.out:
        out_path = Path(args.out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        print(str(out_path))
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
