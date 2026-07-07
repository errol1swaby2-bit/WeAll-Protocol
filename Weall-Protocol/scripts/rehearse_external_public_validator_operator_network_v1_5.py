#!/usr/bin/env python3
from __future__ import annotations

"""Emit a deterministic external-validator transcript scaffold.

This is a release evidence harness scaffold: it defines the minimum transcript
shape and a deterministic local sample, but it deliberately keeps public
validator/public beta/mainnet claims false until independently operated evidence
is attached and validated.
"""

import argparse
import hashlib
import json
from typing import Any

Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def build_transcript() -> Json:
    state_roots = {node: "732fac2dd801a3531c2c5e08129b4708b051f6c6f2318f99648af9718640ed60" for node in ("v-a", "v-b", "v-c", "v-d")}
    core = {
        "schema": "weall.v1_5.public_validator_operator_transcript",
        "blocker": "AUD-618-P0-001",
        "chain_id": "weall-b620-external-validator-evidence-scaffold",
        "operator_ids": ["operator-a", "operator-b", "operator-c", "operator-d"],
        "node_ids": ["v-a", "v-b", "v-c", "v-d"],
        "machine_ids": ["machine-a", "machine-b", "machine-c", "machine-d"],
        "rounds": 6,
        "threshold": 3,
        "fresh_clone": True,
        "node_registration": True,
        "node_operator_readiness": True,
        "validator_candidate_path": True,
        "readiness_receipt": True,
        "activation_rehearsal": True,
        "observer_bypass_rejected": True,
        "restart_fail_closed_without_chain_state_signing": True,
        "state_root_by_node": state_roots,
        "state_roots_match": len(set(state_roots.values())) == 1,
        "partition_rejoin": True,
        "minority_partition_cannot_finalize": True,
        "equivocation_rejected": True,
        "observer_vote_rejected": True,
        "fresh_node_catchup": True,
        "restart_replay": True,
        "operator_signatures": ["external-signature-required-a", "external-signature-required-b", "external-signature-required-c", "external-signature-required-d"],
        "claim_boundaries": {
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics_enabled": False,
        },
        "external_attestation_required": True,
        "sample_transcript_only": True,
    }
    core["transcript_digest"] = _digest({k: v for k, v in core.items() if k != "transcript_digest"})
    return core


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a v1.5 external public-validator operator transcript scaffold.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build_transcript()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(json.dumps({"ok": True, "transcript_digest": payload["transcript_digest"], "public_validator_enabled": False, "external_attestation_required": True}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
