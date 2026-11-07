#!/usr/bin/env python3
"""Read-only, reference-only verification of a signed genesis witness bundle.

This is a cryptographic and manifest-consistency preflight. It does NOT review
witness independence, approve a genesis ceremony, confer validator authority,
or schedule first finality. The manifest digest must have been obtained from
an independent trusted channel; calculating it from the supplied manifest and
passing that result back as an anchor is not independent verification.

Requiring separate manifest and genesis input files avoids silently accepting
a witness receipt's self-declared hash as its own trust root.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weall.runtime.genesis_acceptance_witness import (  # noqa: E402
    GenesisAcceptancePreflightError,
    preflight_genesis_manifest_witness_binding,
)


def _pairs_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate_json_object_key")
        obj[key] = value
    return obj


def _reject_nonfinite(token: str) -> Any:
    raise ValueError("non_finite_json_number")


def _read_object(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(encoding="utf-8")
        obj = json.loads(
            content,
            object_pairs_hook=_pairs_unique,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise GenesisAcceptancePreflightError("invalid_genesis_bundle_json") from exc
    if not isinstance(obj, dict):
        raise GenesisAcceptancePreflightError("genesis_bundle_root_not_object")
    return obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reference-only, fail-closed genesis manifest and witness preflight."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument(
        "--trusted-manifest-sha256",
        required=True,
        help="Must come from an independent trusted source, not the untrusted bundle.",
    )
    parser.add_argument("--expected-chain-id", required=True)
    args = parser.parse_args(argv)

    try:
        evidence = preflight_genesis_manifest_witness_binding(
            manifest=_read_object(args.manifest),
            genesis_ledger=_read_object(args.genesis),
            certificate=_read_object(args.certificate),
            expected_manifest_sha256=args.trusted_manifest_sha256,
            expected_chain_id=args.expected_chain_id,
        )
    except GenesisAcceptancePreflightError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "cryptographic_preflight_failed",
                    "reason": str(exc),
                    "authorizes_first_finality": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2

    print(
        json.dumps(
            {
                "ok": True,
                "status": "cryptographic_preflight_only",
                "scope": "reference_only",
                "authority_decision": "not_performed",
                "evidence": asdict(evidence),
                "authorizes_first_finality": False,
                "external_independence_review_required": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
