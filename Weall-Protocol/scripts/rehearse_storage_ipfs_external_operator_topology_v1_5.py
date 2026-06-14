#!/usr/bin/env python3
from __future__ import annotations

"""Emit a deterministic external storage/IPFS topology transcript scaffold."""

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
    core = {
        "schema": "weall.v1_5.storage_ipfs_operator_transcript",
        "operator_ids": ["storage-operator-a", "storage-operator-b", "storage-operator-c"],
        "machine_ids": ["storage-machine-a", "storage-machine-b", "storage-machine-c"],
        "ipfs_peer_ids": ["12D3KooWsampleA", "12D3KooWsampleB", "12D3KooWsampleC"],
        "cid": "bafybeigdyrztb620samplecidnotpublicdurabilityclaim",
        "replication_factor": 3,
        "origin_failure": True,
        "retrieval_from_non_origin_machine": True,
        "fresh_node_retrieval": True,
        "wrong_cid_rejected": True,
        "corrupt_content_rejected": True,
        "revalidation_exercised": True,
        "operator_signatures": ["external-storage-signature-required-a", "external-storage-signature-required-b", "external-storage-signature-required-c"],
        "claim_boundaries": {
            "public_storage_provider_market": False,
            "public_decentralized_media_durability": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
        },
        "real_daemon_topology_required": True,
        "sample_transcript_only": True,
    }
    core["transcript_digest"] = _digest({k: v for k, v in core.items() if k != "transcript_digest"})
    return core


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a v1.5 external storage/IPFS operator transcript scaffold.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build_transcript()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(json.dumps({"ok": True, "transcript_digest": payload["transcript_digest"], "public_decentralized_media_durability": False, "real_daemon_topology_required": True}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
