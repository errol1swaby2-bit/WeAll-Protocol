#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.operator_incident_diff import diff_operator_incident_reports  # noqa: E402


def _load_json(path_str: str):
    path = Path(path_str).resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two operator incident reports.")
    parser.add_argument("left", help="Path to first incident report JSON")
    parser.add_argument("right", help="Path to second incident report JSON")
    parser.add_argument("--out", default=None, help="Optional output path")
    args = parser.parse_args()

    result = diff_operator_incident_reports(_load_json(args.left), _load_json(args.right))
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
