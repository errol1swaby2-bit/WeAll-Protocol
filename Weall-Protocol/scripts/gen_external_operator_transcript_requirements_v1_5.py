#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 external operator transcript requirements artifact.

This artifact intentionally does not mark public beta or mainnet ready. It turns
remaining external-evidence blockers into deterministic, machine-checkable
schemas so public-beta readiness cannot be claimed without independently
operated validator/storage/legal transcripts attached to a release.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "external_operator_transcript_requirements_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _schema(
    name: str,
    description: str,
    required_fields: list[str],
    required_truths: dict[str, Any],
    forbidden_claims: list[str],
    minimum_counts: dict[str, int] | None = None,
) -> Json:
    return {
        "name": name,
        "description": description,
        "required_fields": required_fields,
        "required_truths": required_truths,
        "minimum_counts": minimum_counts or {},
        "forbidden_claims": forbidden_claims,
    }


def build() -> Json:
    schemas: Json = {
        "public_validator_operator_transcript": _schema(
            "public_validator_operator_transcript",
            "Independently operated public-validator rehearsal transcript. Local simulation is not enough for public beta.",
            [
                "schema",
                "chain_id",
                "operator_ids",
                "node_ids",
                "machine_ids",
                "rounds",
                "threshold",
                "state_root_by_node",
                "partition_rejoin",
                "minority_partition_cannot_finalize",
                "equivocation_rejected",
                "observer_vote_rejected",
                "fresh_node_catchup",
                "restart_replay",
                "transcript_digest",
                "operator_signatures",
                "claim_boundaries",
            ],
            {
                "state_roots_match": True,
                "partition_rejoin": True,
                "minority_partition_cannot_finalize": True,
                "equivocation_rejected": True,
                "observer_vote_rejected": True,
                "fresh_node_catchup": True,
                "restart_replay": True,
                "claim_boundaries.public_validator_enabled": False,
                "claim_boundaries.public_beta_ready": False,
                "claim_boundaries.mainnet_ready": False,
            },
            [
                "mainnet_ready",
                "public_beta_ready_without_release_vote",
                "public_validator_enabled_without_external_attestation",
                "live_economics_enabled",
            ],
            {"operator_ids": 4, "node_ids": 4, "machine_ids": 4, "rounds": 6, "operator_signatures": 4},
        ),
        "storage_ipfs_operator_transcript": _schema(
            "storage_ipfs_operator_transcript",
            "Real daemon/operator IPFS durability transcript proving decentralized media/storage claims before public beta.",
            [
                "schema",
                "operator_ids",
                "machine_ids",
                "ipfs_peer_ids",
                "cid",
                "replication_factor",
                "origin_failure",
                "retrieval_from_non_origin_machine",
                "fresh_node_retrieval",
                "wrong_cid_rejected",
                "corrupt_content_rejected",
                "revalidation_exercised",
                "transcript_digest",
                "operator_signatures",
                "claim_boundaries",
            ],
            {
                "origin_failure": True,
                "retrieval_from_non_origin_machine": True,
                "fresh_node_retrieval": True,
                "wrong_cid_rejected": True,
                "corrupt_content_rejected": True,
                "revalidation_exercised": True,
                "claim_boundaries.public_storage_provider_market": False,
                "claim_boundaries.public_decentralized_media_durability": False,
                "claim_boundaries.public_beta_ready": False,
            },
            [
                "public_storage_market_enabled_without_release_gate",
                "public_decentralized_media_durability_without_real_daemon_topology",
                "private_evidence_publicly_visible",
            ],
            {"operator_ids": 3, "machine_ids": 3, "ipfs_peer_ids": 3, "replication_factor": 3, "operator_signatures": 3},
        ),
        "legal_compliance_attestation": _schema(
            "legal_compliance_attestation",
            "Counsel/control attestation needed before public token, economics, governance, and launch-readiness claims.",
            [
                "schema",
                "review_date",
                "reviewer_or_counsel_reference",
                "scope",
                "approved_public_claims",
                "restricted_claims",
                "launch_matrix_checked",
                "signature_or_controlled_reference",
                "claim_boundaries",
            ],
            {
                "launch_matrix_checked": True,
                "claim_boundaries.legal_compliance_ready": False,
                "claim_boundaries.live_economics": False,
                "claim_boundaries.mainnet_ready": False,
            },
            [
                "legal_compliance_ready_without_counsel_reference",
                "token_sale_ready_without_counsel",
                "live_economics_ready_without_release_gate",
            ],
            {"approved_public_claims": 1, "restricted_claims": 1},
        ),
    }
    validation_commands = {
        name: f"PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind {name} --path <transcript.json>"
        for name in schemas
    }
    return {
        "schema": "weall.v1_5.external_operator_transcript_requirements",
        "version": "2026-06-b620-external-evidence-gates",
        "ok": True,
        "public_beta_ready": False,
        "mainnet_ready": False,
        "external_attestation_required_before_public_beta": True,
        "schemas": schemas,
        "validation_commands": validation_commands,
        "release_claim_boundaries": {
            "controlled_private_testnet_candidate": True,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "public_validator_enabled": False,
            "public_storage_provider_market": False,
            "public_decentralized_media_durability": False,
            "production_helper_execution": False,
            "automatic_protocol_upgrades": False,
            "live_economics": False,
            "legal_compliance_ready": False,
        },
        "artifact_digest": _digest({"schemas": schemas, "validation_commands": validation_commands}),
    }


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check v1.5 external operator transcript requirements.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("external_operator_transcript_requirements_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['schemas'])} transcript schemas)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(payload['schemas'])} transcript schemas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
