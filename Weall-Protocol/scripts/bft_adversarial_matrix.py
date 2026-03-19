#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from weall.runtime.fault_injection import run_bft_fault_injection_soak

SCENARIOS = {
    "partition_restart_rejoin": dict(
        rounds=12,
        validator_count=4,
        partition_rounds=(3, 4, 5),
        restart_every=4,
        delay_child_first_every=3,
    ),
    "stall_recovery": dict(
        rounds=12,
        validator_count=4,
        partition_rounds=(),
        stall_rounds=(4, 5, 6),
        stall_target="v4",
        delay_child_first_every=0,
        restart_every=0,
    ),
    "epoch_shift_rejoin": dict(
        rounds=12,
        validator_count=4,
        partition_rounds=(3, 4),
        restart_every=4,
        epoch_bump_rounds=(6, 9),
        stale_qc_replay_target="v2",
        delay_child_first_every=3,
    ),
    "clock_skew_warning": dict(
        rounds=10,
        validator_count=4,
        clock_skew_target="v4",
        clock_skew_rounds=(2, 3, 6),
        clock_skew_ahead_ms=180_000,
        partition_rounds=(),
        stall_rounds=(),
        delay_child_first_every=3,
        restart_every=0,
    ),
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run a matrix of adversarial local multi-node BFT scenarios."
    )
    ap.add_argument(
        "--work-dir", default="", help="Base directory for scenario state. Defaults to a temp dir."
    )
    ap.add_argument("--chain-id-prefix", default="bft-matrix")
    ap.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="Scenario name to run. Repeatable. Defaults to all scenarios.",
    )
    args = ap.parse_args()

    requested = [s.strip() for s in args.scenario if str(s).strip()] or list(SCENARIOS.keys())
    unknown = [s for s in requested if s not in SCENARIOS]
    if unknown:
        raise SystemExit(f"unknown scenarios: {', '.join(unknown)}")

    base = Path(args.work_dir).resolve() if str(args.work_dir).strip() else None
    results: dict[str, object] = {}
    all_ok = True
    for idx, name in enumerate(requested, start=1):
        scenario_dir = str((base / name).resolve()) if base is not None else None
        summary = run_bft_fault_injection_soak(
            work_dir=scenario_dir,
            chain_id=f"{args.chain_id_prefix}-{idx}-{name}",
            **SCENARIOS[name],
        )
        payload = summary.to_json()
        payload["scenario"] = name
        results[name] = payload
        all_ok = all_ok and bool(payload.get("converged", False))

    output = {
        "ok": all_ok,
        "scenario_count": len(results),
        "scenarios": results,
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
