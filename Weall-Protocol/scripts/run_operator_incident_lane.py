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
from weall.runtime.operator_incident_lane import build_operator_incident_lane  # noqa: E402


def _load_optional_json(path_str: str | None):
    if not path_str:
        return None
    path = Path(path_str).resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return payload


def _load_peer_reports(paths: list[str] | None):
    reports = []
    for raw in paths or []:
        path = Path(raw).resolve()
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"{path} must contain a JSON object")
        reports.append(payload)
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an operator incident lane bundle: report, actions, safe mode, and peer divergence summary."
    )
    parser.add_argument("--db-path", default=None, help="Path to node SQLite DB. Defaults to chain config db_path.")
    parser.add_argument("--tx-index-path", default=None, help="Path to generated tx index. Defaults to chain config tx_index_path.")
    parser.add_argument("--remote-forensics", default=None, help="Optional path to remote consensus forensics JSON.")
    parser.add_argument(
        "--peer-report",
        dest="peer_reports",
        action="append",
        default=None,
        help="Optional path to a peer operator incident report JSON. May be passed multiple times.",
    )
    parser.add_argument("--out", default=None, help="Optional output path. Prints to stdout when omitted.")
    args = parser.parse_args()

    cfg = load_chain_config()
    db_path = Path(args.db_path or cfg.db_path).resolve()
    tx_index_path = Path(args.tx_index_path or cfg.tx_index_path).resolve()
    remote = _load_optional_json(args.remote_forensics)
    peers = _load_peer_reports(args.peer_reports)

    lane = build_operator_incident_lane(
        cfg=cfg,
        db_path=db_path,
        tx_index_path=tx_index_path,
        remote_forensics=remote,
        peer_reports=peers,
    )
    rendered = json.dumps(lane, indent=2, sort_keys=True)

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
