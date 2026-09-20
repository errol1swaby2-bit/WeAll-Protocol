#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from rehearse_anti_sybil_adjudication_deletion_v1_5 import (
    run_harness as run_anti_sybil_adjudication,
)
from rehearse_autonomous_validator_gossip_loop_v1_5 import run_harness as run_autonomous_validator
from rehearse_economics_locked_read_models_v1_5 import run_harness as run_economics_read_models
from rehearse_fresh_node_catchup_autonomous_network_v1_5 import run_harness as run_fresh_catchup
from rehearse_multiprocess_ipfs_operator_durability_v1_5 import run_harness as run_ipfs_multiprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b567_b571_autonomous_mechanics_proof_v1_5.json"

INPUT_FILES = [
    Path(__file__).resolve(),
    ROOT / "scripts" / "rehearse_autonomous_validator_gossip_loop_v1_5.py",
    ROOT / "scripts" / "rehearse_fresh_node_catchup_autonomous_network_v1_5.py",
    ROOT / "scripts" / "rehearse_multiprocess_ipfs_operator_durability_v1_5.py",
    ROOT / "scripts" / "rehearse_anti_sybil_adjudication_deletion_v1_5.py",
    ROOT / "scripts" / "rehearse_economics_locked_read_models_v1_5.py",
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


def _validate_contract(artifact: dict[str, Any]) -> None:
    if artifact.get("schema") != "weall.v1_5.batch567_571.autonomous_mechanics_proof":
        raise ValueError("b567_schema_invalid")
    if artifact.get("batch_range") != "567-571":
        raise ValueError("b567_batch_range_invalid")
    if artifact.get("ok") is not True:
        raise ValueError("b567_live_contract_not_ok")
    if artifact.get("public_beta_ready") is not False:
        raise ValueError("b567_public_beta_claim_must_remain_false")


def build() -> dict[str, Any]:
    autonomous = run_autonomous_validator()
    catchup = run_fresh_catchup()
    storage = run_ipfs_multiprocess()
    anti_sybil = run_anti_sybil_adjudication()
    economics = run_economics_read_models()
    boundaries = {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_multi_validator_bft": False,
        "public_validator_readiness": False,
    }
    return {
        "schema": "weall.v1_5.batch567_571.autonomous_mechanics_proof",
        "batch_range": "567-571",
        "freshness": {
            "input_digest_sha256": _input_digest(),
            "mode": "deterministic_input_digest_v1",
        },
        "ok": all(bool(x.get("ok")) for x in (autonomous, catchup, storage, anti_sybil, economics)),
        "autonomous_validator_gossip_loop": autonomous,
        "fresh_node_catchup_autonomous_network": catchup,
        "multiprocess_ipfs_operator_durability": storage,
        "anti_sybil_adjudication_deletion": anti_sybil,
        "economics_locked_read_models": economics,
        "controlled_testnet_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": boundaries,
        "remaining_gaps": [
            "autonomous validator gossip is modeled in local threaded processes; public validator readiness still requires multi-machine independent operators and full production transport under adversarial timing",
            "fresh-node catch-up validates live-peer commit logs, but public network churn and malicious peer diversity require broader soak tests",
            "storage durability now uses multi-process IPFS-compatible workers, but public media durability still requires multi-daemon or multi-machine IPFS operator rehearsal",
            "anti-Sybil adjudication and evidence deletion execution exist, but automatic duplicate-human detection and legal/privacy review remain outside the current claim",
            "economics read models exist while locked; live economics remains disabled pending legal, treasury, wallet UX, and long-run economic review",
        ],
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--verify-live", action="store_true")
    args = ap.parse_args()

    if args.check and args.verify_live:
        ap.error("--check and --verify-live are mutually exclusive")

    if args.check:
        if not OUT.exists():
            raise SystemExit(
                "b567_b571_autonomous_mechanics_proof_v1_5.json is missing; rerun generator"
            )
        try:
            stored = json.loads(OUT.read_text(encoding="utf-8"))
            _validate_contract(stored)
        except Exception as exc:
            raise SystemExit(f"b567 artifact invalid:{type(exc).__name__}:{exc}") from exc
        freshness = stored.get("freshness") if isinstance(stored.get("freshness"), dict) else {}
        if freshness.get("mode") != "deterministic_input_digest_v1":
            raise SystemExit("b567 artifact freshness mode is stale; rerun generator")
        if freshness.get("input_digest_sha256") != _input_digest():
            raise SystemExit("b567 artifact input digest is stale; rerun generator")
        if OUT.read_text(encoding="utf-8") != _canon(stored):
            raise SystemExit("b567 artifact canonical JSON formatting is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh (deterministic input digest)")
        return 0

    artifact = build()
    _validate_contract(artifact)
    if args.verify_live:
        if not OUT.exists():
            raise SystemExit("b567 live verification requires the checked-in artifact")
        try:
            stored = json.loads(OUT.read_text(encoding="utf-8"))
            _validate_contract(stored)
        except Exception as exc:
            raise SystemExit(f"b567 stored artifact invalid:{type(exc).__name__}:{exc}") from exc
        if _canon(stored) != _canon(artifact):
            raise SystemExit("b567 live verification diverged from checked-in artifact")
        print(
            json.dumps(
                {
                    "ok": True,
                    "artifact": OUT.relative_to(ROOT).as_posix(),
                    "input_digest_sha256": artifact["freshness"]["input_digest_sha256"],
                    "live_artifact_equivalence": True,
                    "live_contract_verified": True,
                },
                sort_keys=True,
            )
        )
        return 0

    text = _canon(artifact)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
