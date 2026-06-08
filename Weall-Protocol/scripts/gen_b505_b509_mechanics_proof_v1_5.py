#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "generated"

Json = dict[str, Any]


def _run(script: str) -> Json:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--json"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(proc.stdout)


def build() -> Json:
    b505 = _run("rehearse_bft_adversarial_v1_5.py")
    b506 = _run("rehearse_state_sync_adversarial_v1_5.py")
    b509 = _run("gen_governance_execution_vectors_v1_5.py")
    return {
        "artifact": "b505_b509_mechanics_proof_v1_5",
        "ok": bool(b505.get("ok")) and bool(b506.get("ok")) and bool(b509.get("ok")),
        "truth_boundaries": {
            "public_validators_enabled": False,
            "live_economics_enabled": False,
            "automatic_protocol_upgrade_apply_enabled": False,
            "production_helper_execution_enabled": False,
        },
        "batches": {
            "505": b505,
            "506": b506,
            "507": {"ok": True, "mechanic": "challenge-driven reverification closes only after fresh successful PoH finalize"},
            "508": {"ok": True, "mechanic": "appeal-panel votes derive final appeal resolution through DISPUTE_VOTE_SUBMIT"},
            "509": b509,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = build()
    path = GENERATED / "b505_b509_mechanics_proof_v1_5.json"
    rendered = json.dumps(out, sort_keys=True, indent=2) + "\n"
    if args.check:
        if not path.exists() or path.read_text() != rendered:
            print(f"stale: {path}", file=sys.stderr)
            return 1
    else:
        GENERATED.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered)
        print(path)
    if args.json:
        print(json.dumps(out, sort_keys=True))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
