#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE = ROOT / "generated" / "tx_lifecycle_assurance_v1_5.json"
GENERATOR = ROOT / "scripts" / "gen_tx_lifecycle_assurance_v1_5.py"
HASH_SEEDS = ("0", "1", "7", "42")


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reverse_mappings(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _reverse_mappings(value[key])
            for key in reversed(list(value.keys()))
        }
    if isinstance(value, list):
        return [_reverse_mappings(item) for item in value]
    return value


def _projection(payload: dict[str, Any]) -> dict[str, Any]:
    rows = payload.get("rows")
    if not isinstance(rows, list) or len(rows) != 236:
        raise RuntimeError("lifecycle_manifest_requires_exactly_236_rows")

    projected_rows: list[dict[str, Any]] = []
    for row in rows:
        success = row.get("successful_execution") if isinstance(row, dict) else None
        if not isinstance(success, dict):
            raise RuntimeError("missing_successful_execution")
        projected_rows.append(
            {
                "tx_type": str(row.get("tx_type") or ""),
                "domain": str(row.get("domain") or ""),
                "origin": str(row.get("origin") or ""),
                "context": str(row.get("context") or ""),
                "receipt_only": bool(row.get("receipt_only")),
                "state_root_before": str(success.get("state_root_before") or ""),
                "state_root_after": str(success.get("state_root_after") or ""),
                "success_receipt": success.get("success_receipt"),
                "failure_vector": (
                    row.get("failure_expectation", {}).get("vector")
                    if isinstance(row.get("failure_expectation"), dict)
                    else None
                ),
                "duplicate_replay_expectation": row.get("duplicate_replay_expectation"),
                "persistence_restart_expectation": row.get("persistence_restart_expectation"),
            }
        )
    projected_rows.sort(key=lambda item: item["tx_type"])
    return {
        "summary": payload.get("summary"),
        "rows": projected_rows,
    }


def _render_digest_for_seed(seed: str) -> str:
    code = """
import hashlib
import importlib.util
from pathlib import Path
path = Path(r'%s')
spec = importlib.util.spec_from_file_location('_a04_lifecycle_generator', path)
if spec is None or spec.loader is None:
    raise SystemExit('generator_import_failed')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(hashlib.sha256(module.render_manifest().encode('utf-8')).hexdigest())
""" % str(GENERATOR)
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = str(seed)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"hash_seed_render_failed:{seed}:{proc.stderr.strip() or proc.stdout.strip()}"
        )
    digest = proc.stdout.strip().splitlines()[-1].strip()
    if len(digest) != 64:
        raise RuntimeError(f"invalid_hash_seed_digest:{seed}:{digest}")
    return digest


def build_probe() -> dict[str, Any]:
    payload = json.loads(LIFECYCLE.read_text(encoding="utf-8"))
    projection = _projection(payload)
    projection_sha = _digest(projection)
    reversed_sha = _digest(_reverse_mappings(projection))

    seed_digests = {seed: _render_digest_for_seed(seed) for seed in HASH_SEEDS}
    unique_seed_digests = sorted(set(seed_digests.values()))

    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    domains = sorted(
        {
            str(row.get("domain") or "")
            for row in payload.get("rows", [])
            if isinstance(row, dict) and str(row.get("domain") or "")
        }
    )
    expected_counts_ok = all(
        int(summary.get(key) or 0) == 236
        for key in (
            "tx_count",
            "successful_apply_count",
            "successful_admission_count",
            "failure_stage_vector_count",
            "receipt_expectation_count",
            "duplicate_replay_expectation_count",
        )
    )

    ok = (
        expected_counts_ok
        and projection_sha == reversed_sha
        and len(unique_seed_digests) == 1
        and unique_seed_digests[0] == _sha256(LIFECYCLE)
    )
    return {
        "schema": "weall.v1_5.a04_cross_machine_determinism_probe",
        "ok": ok,
        "tx_count": int(summary.get("tx_count") or 0),
        "domain_count": len(domains),
        "domains": domains,
        "lifecycle_manifest_sha256": _sha256(LIFECYCLE),
        "lifecycle_projection_sha256": projection_sha,
        "reversed_insertion_projection_sha256": reversed_sha,
        "insertion_order_invariant": projection_sha == reversed_sha,
        "hash_seed_render_sha256": seed_digests,
        "hash_seed_render_match": len(unique_seed_digests) == 1,
        "hash_seeds": list(HASH_SEEDS),
        "expected_236_contract_counts": expected_counts_ok,
        "claim_boundaries": {
            "external_cross_machine_evidence_complete": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = build_probe()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
