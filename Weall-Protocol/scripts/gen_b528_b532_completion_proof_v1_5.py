#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from rehearse_api_driven_full_lifecycle_v1_5 import run_harness as run_api_lifecycle
from rehearse_db_backed_fresh_node_replay_sync_v1_5 import run_harness as run_db_replay
from rehearse_live_node_process_validator_network_v1_5 import run_harness as run_live_validator

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b528_b532_completion_proof_v1_5.json"
INPUT_FILES = [
    Path(__file__).resolve(),
    ROOT / "scripts" / "rehearse_live_node_process_validator_network_v1_5.py",
    ROOT / "scripts" / "rehearse_db_backed_fresh_node_replay_sync_v1_5.py",
    ROOT / "scripts" / "rehearse_api_driven_full_lifecycle_v1_5.py",
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


def _validate_contract(data: dict[str, Any]) -> None:
    if data.get("artifact") != "b528_b532_completion_proof_v1_5":
        raise ValueError("b528_artifact_identity_invalid")
    if data.get("batches") != [528, 529, 530, 531, 532]:
        raise ValueError("b528_batch_range_invalid")
    if data.get("ok") is not True:
        raise ValueError("b528_live_contract_not_ok")
    if any(bool(v) for v in (data.get("locked_boundaries") or {}).values()):
        raise ValueError("b528_locked_boundary_must_remain_false")


def build() -> dict[str, Any]:
    validator = run_live_validator()
    replay = run_db_replay()
    lifecycle = run_api_lifecycle()
    feed = lifecycle.get("feed_ranking", {}) if isinstance(lifecycle, dict) else {}
    locked = {
        "public_validators": False,
        "live_economics": False,
        "automatic_upgrades": False,
        "production_helpers": False,
    }
    return {
        "ok": bool(
            validator.get("ok")
            and replay.get("ok")
            and lifecycle.get("ok")
            and not any(locked.values())
        ),
        "artifact": "b528_b532_completion_proof_v1_5",
        "batches": [528, 529, 530, 531, 532],
        "freshness": {
            "input_digest_sha256": _input_digest(),
            "mode": "deterministic_input_digest_v1",
        },
        "scope": [
            "tcp_process_validator_rehearsal",
            "sqlite_db_backed_fresh_node_replay_sync",
            "api_driven_full_lifecycle",
            "poh_dispute_accountability_completion",
            "economics_storage_activation_complete_locked",
            "production_social_feed_ranking",
        ],
        "locked_boundaries": locked,
        "validator_rehearsal": validator,
        "fresh_node_replay_sync": replay,
        "api_lifecycle": lifecycle,
        "feed_ranking": {
            "mode": feed.get("mode"),
            "complete_for_deterministic_public_social_ranking": bool(
                feed.get("production_social_feed")
                and feed.get("uses_reputation_weighting")
                and feed.get("uses_anti_brigading_caps")
            ),
            "complete_for_personalized_recommendation": False,
            "personalized": False,
            "uses_reputation_weighting": bool(feed.get("uses_reputation_weighting")),
            "uses_anti_brigading_caps": bool(feed.get("uses_anti_brigading_caps")),
            "uses_author_diversity_dampening": bool(feed.get("uses_author_diversity_dampening")),
            "cursor_model": feed.get("cursor_model"),
        },
        "truth_boundary": "local_private_completion_rehearsal_not_public_beta_or_mainnet",
    }


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
            raise SystemExit("b528_b532_completion_proof_v1_5.json is missing; rerun generator")
        try:
            stored = json.loads(OUT.read_text(encoding="utf-8"))
            _validate_contract(stored)
        except Exception as exc:
            raise SystemExit(f"b528 artifact invalid:{type(exc).__name__}:{exc}") from exc
        freshness = stored.get("freshness") if isinstance(stored.get("freshness"), dict) else {}
        if freshness.get("mode") != "deterministic_input_digest_v1":
            raise SystemExit("b528 artifact freshness mode is stale; rerun generator")
        if freshness.get("input_digest_sha256") != _input_digest():
            raise SystemExit("b528 artifact input digest is stale; rerun generator")
        if OUT.read_text(encoding="utf-8") != _canon(stored):
            raise SystemExit("b528 artifact canonical JSON formatting is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh (deterministic input digest)")
        return 0

    data = build()
    _validate_contract(data)

    if args.verify_live:
        if not OUT.exists():
            raise SystemExit("b528 live verification requires the checked-in artifact")
        try:
            stored = json.loads(OUT.read_text(encoding="utf-8"))
            _validate_contract(stored)
        except Exception as exc:
            raise SystemExit(f"b528 stored artifact invalid:{type(exc).__name__}:{exc}") from exc
        if _canon(stored) != _canon(data):
            raise SystemExit("b528 live verification diverged from checked-in artifact")
        print(
            json.dumps(
                {
                    "ok": True,
                    "artifact": OUT.relative_to(ROOT).as_posix(),
                    "input_digest_sha256": data["freshness"]["input_digest_sha256"],
                    "live_artifact_equivalence": True,
                    "live_contract_verified": True,
                },
                sort_keys=True,
            )
        )
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(_canon(data), encoding="utf-8")
    if args.json:
        print(json.dumps(data, sort_keys=True))
    else:
        print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
