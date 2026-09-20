#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from rehearse_full_node_process_controlled_validator_v1_5 import run_harness as run_validator
from rehearse_fully_api_driven_v15_lifecycle import run_harness as run_lifecycle
from rehearse_real_db_block_commit_replay_sync_v1_5 import run_harness as run_replay
from rehearse_storage_operator_durability_v1_5 import run_harness as run_storage

OUT = ROOT / "generated" / "b534_b538_completion_proof_v1_5.json"
INPUT_FILES = [
    Path(__file__).resolve(),
    ROOT / "scripts" / "rehearse_full_node_process_controlled_validator_v1_5.py",
    ROOT / "scripts" / "rehearse_real_db_block_commit_replay_sync_v1_5.py",
    ROOT / "scripts" / "rehearse_fully_api_driven_v15_lifecycle.py",
    ROOT / "scripts" / "rehearse_storage_operator_durability_v1_5.py",
]


def _input_digest() -> str:
    h = hashlib.sha256()
    files = list(INPUT_FILES)
    files.extend(sorted((ROOT / "src" / "weall").rglob("*.py")))
    for path in sorted(set(files), key=lambda p: p.relative_to(ROOT).as_posix()):
        rel = path.relative_to(ROOT).as_posix().encode("utf-8")
        h.update(len(rel).to_bytes(4, "big"))
        h.update(rel)
        data = path.read_bytes()
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def _validate_contract(proof: dict[str, Any]) -> None:
    if proof.get("artifact") != "b534_b538_completion_proof_v1_5":
        raise ValueError("b534_artifact_identity_invalid")
    if proof.get("batches") != ["534", "535", "536", "537", "538"]:
        raise ValueError("b534_batch_range_invalid")
    if proof.get("ok") is not True:
        raise ValueError("b534_live_contract_not_ok")
    if any(bool(v) for v in (proof.get("locked_boundaries") or {}).values()):
        raise ValueError("b534_locked_boundary_must_remain_false")


def build() -> dict[str, Any]:
    validator = run_validator()
    replay = run_replay()
    lifecycle = run_lifecycle()
    storage = run_storage()
    proof = {
        "artifact": "b534_b538_completion_proof_v1_5",
        "batches": ["534", "535", "536", "537", "538"],
        "freshness": {
            "input_digest_sha256": _input_digest(),
            "mode": "deterministic_input_digest_v1",
        },
        "ok": all(bool(x.get("ok")) for x in [validator, replay, lifecycle, storage]),
        "scope": [
            "full_node_process_controlled_validator_rehearsal",
            "real_db_block_commit_replay_sync",
            "api_driven_v15_lifecycle",
            "poh_dispute_remedy_reinstatement",
            "storage_operator_durability_rehearsal",
        ],
        "validator_rehearsal": validator,
        "replay_sync": replay,
        "api_lifecycle": lifecycle,
        "storage_durability": storage,
        "locked_boundaries": {
            "public_validators": False,
            "live_economics": False,
            "automatic_upgrades": False,
            "production_helpers": False,
        },
        "truth_boundary": "local_private_full_node_process_rehearsal_not_public_beta_or_mainnet",
    }
    return proof


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-live", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.check and args.verify_live:
        parser.error("--check and --verify-live are mutually exclusive")

    if args.check:
        if not OUT.exists():
            raise SystemExit("b534_b538_completion_proof_v1_5.json is missing; rerun generator")
        try:
            stored = json.loads(OUT.read_text(encoding="utf-8"))
            _validate_contract(stored)
        except Exception as exc:
            raise SystemExit(f"b534 artifact invalid:{type(exc).__name__}:{exc}") from exc
        freshness = stored.get("freshness") if isinstance(stored.get("freshness"), dict) else {}
        if freshness.get("mode") != "deterministic_input_digest_v1":
            raise SystemExit("b534 artifact freshness mode is stale; rerun generator")
        if freshness.get("input_digest_sha256") != _input_digest():
            raise SystemExit("b534 artifact input digest is stale; rerun generator")
        if OUT.read_text(encoding="utf-8") != _canon(stored):
            raise SystemExit("b534 artifact canonical JSON formatting is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh (deterministic input digest)")
        return 0

    proof = build()
    _validate_contract(proof)

    if args.verify_live:
        if not OUT.exists():
            raise SystemExit("b534 live verification requires the checked-in artifact")
        try:
            stored = json.loads(OUT.read_text(encoding="utf-8"))
            _validate_contract(stored)
        except Exception as exc:
            raise SystemExit(f"b534 stored artifact invalid:{type(exc).__name__}:{exc}") from exc
        if _canon(stored) != _canon(proof):
            raise SystemExit("b534 live verification diverged from checked-in artifact")
        print(
            json.dumps(
                {
                    "ok": True,
                    "artifact": OUT.relative_to(ROOT).as_posix(),
                    "input_digest_sha256": proof["freshness"]["input_digest_sha256"],
                    "live_artifact_equivalence": True,
                    "live_contract_verified": True,
                },
                sort_keys=True,
            )
        )
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(_canon(proof), encoding="utf-8")
    if args.json:
        print(json.dumps(proof, sort_keys=True))
    else:
        print(str(OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
