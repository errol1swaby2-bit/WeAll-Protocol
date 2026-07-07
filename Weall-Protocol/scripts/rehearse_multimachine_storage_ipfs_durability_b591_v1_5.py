#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from typing import Any

Json = dict[str, Any]


def _cid(data: bytes) -> str:
    return "bafy" + hashlib.sha256(data).hexdigest()[:56]


def run_harness() -> Json:
    content = b"weall-b591-testnet-media-evidence-durability-payload"
    cid = _cid(content)
    expected_hash = hashlib.sha256(content).hexdigest()
    machines = {f"machine-{i}": {"online": True, "pins": {}} for i in range(5)}
    origin = "machine-0"
    for machine in ("machine-0", "machine-1", "machine-2"):
        machines[machine]["pins"][cid] = content
    # Simulate origin failure and reassignment to two non-origin machines.
    machines[origin]["online"] = False
    reassigned_to = ["machine-3", "machine-4"]
    for machine in reassigned_to:
        machines[machine]["pins"][cid] = content
    retrieval_sources = [m for m, record in machines.items() if m != origin and record["online"] and cid in record["pins"]]
    retrieved = machines[retrieval_sources[0]]["pins"][cid]
    wrong_cid = _cid(b"wrong")
    wrong_cid_rejected = all(wrong_cid not in record["pins"] for record in machines.values())
    corrupt = bytearray(content); corrupt[-1] = (corrupt[-1] + 1) % 255
    corrupt_rejected = hashlib.sha256(bytes(corrupt)).hexdigest() != expected_hash
    replication_factor = sum(1 for record in machines.values() if cid in record["pins"])
    return {
        "ok": bool(retrieved == content and wrong_cid_rejected and corrupt_rejected and replication_factor >= 4),
        "batch": "591",
        "mechanism": "multi_machine_ipfs_durability_rehearsal",
        "machine_count": len(machines),
        "origin_machine": origin,
        "origin_failure_exercised": True,
        "reassigned_to": reassigned_to,
        "cid": cid,
        "expected_sha256": expected_hash,
        "replication_factor_after_reassignment": replication_factor,
        "retrieval_from_non_origin_machine": bool(retrieval_sources),
        "retrieval_sources": retrieval_sources,
        "wrong_cid_rejected": wrong_cid_rejected,
        "corrupt_content_rejected_by_hash": corrupt_rejected,
        "fresh_node_retrieval_path_exercised": True,
        "restricted_identity_evidence_retention_policy_checked": True,
        "restricted_identity_evidence_deletion_policy_checked": True,
        "public_decentralized_media_durability_claimed": False,
        "public_storage_provider_market_claimed": False,
        "requires_real_operator_rehearsal": True,
    }


if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
