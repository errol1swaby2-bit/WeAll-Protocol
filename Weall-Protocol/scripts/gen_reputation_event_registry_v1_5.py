#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from weall.runtime.reputation_events import registry_payload  # noqa: E402

OUT = ROOT / "generated" / "reputation_event_registry_v1_5.json"


def render(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    payload = registry_payload()
    text = render(payload)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
        return 0
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"stale generated artifact: {OUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print(f"OK: {OUT.relative_to(ROOT)} is current ({payload['event_count']} events)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
