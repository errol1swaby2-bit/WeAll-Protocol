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

from weall.runtime.chain_config import load_chain_config  # noqa: E402
from weall.runtime.operator_incident_lane import (  # noqa: E402
    build_operator_incident_lane,
    build_operator_incident_lane_summary,
)
from weall.runtime.operator_incident_report import build_operator_incident_report  # noqa: E402


def _load_optional_json(path_str: str | None):
    if not path_str:
        return None
    path = Path(path_str).resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("remote forensics JSON must be an object")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an operator incident report from local node state and optional remote consensus forensics."
    )
    parser.add_argument("--db-path", default=None, help="Path to node SQLite DB. Defaults to chain config db_path.")
    parser.add_argument("--tx-index-path", default=None, help="Path to generated tx index. Defaults to chain config tx_index_path.")
    parser.add_argument("--remote-forensics", default=None, help="Optional path to previously captured consensus forensics JSON.")
    parser.add_argument("--out", default=None, help="Optional output path. Prints to stdout when omitted.")
    parser.add_argument(
        "--lane-out",
        default=None,
        help="Optional path to also write an operator incident lane bundle for observer-first recovery.",
    )
    parser.add_argument(
        "--include-lane-summary",
        action="store_true",
        help="Embed a condensed incident-lane summary into the report payload.",
    )
    args = parser.parse_args()

    cfg = load_chain_config()
    db_path = Path(args.db_path or cfg.db_path).resolve()
    tx_index_path = Path(args.tx_index_path or cfg.tx_index_path).resolve()
    remote = _load_optional_json(args.remote_forensics)

    report = build_operator_incident_report(
        cfg=cfg,
        db_path=db_path,
        tx_index_path=tx_index_path,
        remote_forensics=remote,
    )

    lane = None
    if args.lane_out or args.include_lane_summary:
        lane = build_operator_incident_lane(
            cfg=cfg,
            db_path=db_path,
            tx_index_path=tx_index_path,
            remote_forensics=remote,
            peer_reports=[],
        )
        if args.include_lane_summary:
            report = {
                **report,
                "incident_lane": build_operator_incident_lane_summary(lane),
            }

    rendered = json.dumps(report, indent=2, sort_keys=True)

    if args.out:
        out_path = Path(args.out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        print(str(out_path))
    else:
        print(rendered)

    if args.lane_out and lane is not None:
        lane_path = Path(args.lane_out).resolve()
        lane_path.parent.mkdir(parents=True, exist_ok=True)
        lane_path.write_text(json.dumps(lane, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.out:
            print(str(lane_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
