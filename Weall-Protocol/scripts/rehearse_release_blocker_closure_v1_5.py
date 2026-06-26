#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"script_load_failed:{path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _file_contains(path: Path, *needles: str) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path.relative_to(ROOT)), "exists": False, "missing": list(needles)}
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [needle for needle in needles if needle not in text]
    return {"path": str(path.relative_to(ROOT)), "exists": True, "missing": missing, "ok": not missing}


def run_harness() -> dict[str, Any]:
    promoted_validator_mempool = _load_script("rehearse_genesis_observer_promoted_validator_mempool_v1_5.py").run_harness()
    process_net = _load_script("rehearse_independent_process_validator_network_v1_5.py").run_harness()

    external_observer = {
        "bundle_builder": _file_contains(
            ROOT / "scripts" / "build_external_observer_bundle.py",
            "manifest",
            "observer",
        ),
        "signed_onboarding_e2e": _file_contains(
            ROOT / "tests" / "prod" / "test_external_observer_signed_onboarding_tx_e2e.py",
            "observer",
            "signed",
        ),
        "runbook": _file_contains(
            ROOT / "docs" / "EXTERNAL_OBSERVER_BUNDLE_RUNBOOK.md",
            "observer bundle",
            "signed transaction path",
            "validator secrets",
        ),
    }
    external_observer["ok"] = all(bool(v.get("ok")) for v in external_observer.values() if isinstance(v, dict))

    docs = {
        "controlled_rehearsal_runbook": _file_contains(
            ROOT / "docs" / "CONTROLLED_TESTNET_GENESIS_TO_VALIDATOR_REHEARSAL.md",
            "Genesis",
            "observer",
            "promoted validator",
            "mempool",
        )
    }

    return {
        "ok": bool(promoted_validator_mempool.get("ok")) and bool(process_net.get("ok")) and bool(external_observer.get("ok")),
        "batch": "616",
        "claims": {
            "controlled_multi_node_testnet_candidate": True,
            "public_validator_ready": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "production_helper_execution_ready": False,
        },
        "local_genesis_observer_promoted_validator_mempool": promoted_validator_mempool,
        "independent_process_validator_finality_restart": process_net,
        "external_observer_bundle_signed_onboarding_surface": external_observer,
        "docs": docs,
        "truth_boundary": "Batch 616 adds exact responsibility consent and release-gate proof surfaces; public validator readiness remains blocked until externally operated multi-machine BFT evidence is attached.",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write-report", default="")
    args = ap.parse_args(argv)
    report = run_harness()
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.write_report:
        out = Path(args.write_report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    print(text if args.json else f"OK: batch616={report['ok']}")
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
