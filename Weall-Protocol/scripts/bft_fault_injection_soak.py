#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from weall.runtime.fault_injection import run_bft_fault_injection_soak


def _parse_int_csv(value: str) -> list[int]:
    out: list[int] = []
    for raw in str(value or "").split(","):
        s = raw.strip()
        if not s:
            continue
        out.append(int(s))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run a local BFT soak/fault-injection harness against WeAll executors."
    )
    ap.add_argument(
        "--work-dir",
        default="",
        help="Directory for per-node sqlite databases. Defaults to a temp dir.",
    )
    ap.add_argument("--rounds", type=int, default=18)
    ap.add_argument("--validator-count", type=int, default=4)
    ap.add_argument("--partition-target", default="")
    ap.add_argument("--partition-rounds", default="5,6,7")
    ap.add_argument("--stall-target", default="")
    ap.add_argument("--stall-rounds", default="")
    ap.add_argument("--delay-target", default="")
    ap.add_argument("--delay-child-first-every", type=int, default=4)
    ap.add_argument("--restart-target", default="")
    ap.add_argument("--restart-every", type=int, default=6)
    ap.add_argument("--epoch-bump-rounds", default="")
    ap.add_argument("--stale-qc-replay-target", default="")
    ap.add_argument("--clock-skew-target", default="")
    ap.add_argument("--clock-skew-rounds", default="")
    ap.add_argument("--clock-skew-ahead-ms", type=int, default=120000)
    ap.add_argument("--chain-id", default="bft-soak")
    ap.add_argument("--validator-epoch", type=int, default=3)
    ap.add_argument("--tx-index-path", default="")
    args = ap.parse_args()

    summary = run_bft_fault_injection_soak(
        work_dir=str(Path(args.work_dir).resolve()) if str(args.work_dir).strip() else None,
        rounds=int(args.rounds),
        validator_count=int(args.validator_count),
        partition_target=str(args.partition_target or "") or None,
        partition_rounds=_parse_int_csv(args.partition_rounds),
        stall_target=str(args.stall_target or "") or None,
        stall_rounds=_parse_int_csv(args.stall_rounds),
        delay_target=str(args.delay_target or "") or None,
        delay_child_first_every=int(args.delay_child_first_every),
        restart_target=str(args.restart_target or "") or None,
        restart_every=int(args.restart_every),
        epoch_bump_rounds=_parse_int_csv(args.epoch_bump_rounds),
        stale_qc_replay_target=str(args.stale_qc_replay_target or "") or None,
        clock_skew_target=str(args.clock_skew_target or "") or None,
        clock_skew_rounds=_parse_int_csv(args.clock_skew_rounds),
        clock_skew_ahead_ms=int(args.clock_skew_ahead_ms),
        chain_id=str(args.chain_id),
        validator_epoch=int(args.validator_epoch),
        tx_index_path=str(args.tx_index_path or "") or None,
    )
    print(json.dumps(summary.to_json(), sort_keys=True, indent=2))
    return 0 if summary.converged else 1


if __name__ == "__main__":
    raise SystemExit(main())
