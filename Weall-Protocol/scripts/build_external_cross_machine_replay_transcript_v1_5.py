#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

Json = dict[str, Any]
_REQUIRED_SEEDS = ("1", "7", "31337")


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest_without_self(payload: Json) -> str:
    material = {key: value for key, value in payload.items() if key != "transcript_digest"}
    return hashlib.sha256(_canon(material).encode("utf-8")).hexdigest()


def _read_packet(path: Path) -> Json:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: packet root must be an object")
    if payload.get("schema") != "weall.v1_5.external_cross_machine_replay_local_packet":
        raise ValueError(f"{path}: wrong packet schema")
    return payload


def _one_value(packets: list[Json], key: str) -> Any:
    values = [_canon(packet.get(key)) for packet in packets]
    if len(set(values)) != 1:
        raise ValueError(f"packet mismatch: {key}")
    return packets[0].get(key)


def _require_packet(packet: Json, *, path: Path) -> None:
    for key in (
        "machine_id",
        "operator_id",
        "commit",
        "git_tree",
        "state_root_vectors_sha256",
        "tx_index_sha256",
        "tx_contract_map_sha256",
        "tx_lifecycle_assurance_sha256",
        "tx_semantic_assurance_sha256",
        "broad_probe_lifecycle_manifest_sha256",
        "broad_probe_lifecycle_projection_sha256",
        "broad_probe_reversed_projection_sha256",
        "broad_probe_hash_seed_render_sha256",
        "replay_manifest_digest",
        "db_replay_digest",
        "fresh_node_replay_digest",
        "state_root",
        "fresh_state_root",
        "hashseed_results",
    ):
        if packet.get(key) in (None, "", [], {}):
            raise ValueError(f"{path}: missing {key}")

    if str(packet.get("git_status_short") or "").strip():
        raise ValueError(f"{path}: packet was not captured from a clean checkout")

    for key in (
        "replay_consistency_ok",
        "fresh_node_replay_sync_ok",
        "db_backed_replay_sync_ok",
        "broad_lifecycle_corpus_ok",
        "broad_probe_ok",
        "broad_probe_insertion_order_invariant",
        "broad_probe_hash_seed_render_match",
        "scheduler_order_permutation_ok",
        "helper_serial_equivalence_ok",
        "failed_receipt_replay_ok",
    ):
        if packet.get(key) is not True:
            raise ValueError(f"{path}: required proof is not true: {key}")

    seeds = packet.get("hashseed_results")
    if not isinstance(seeds, dict):
        raise ValueError(f"{path}: hashseed_results must be an object")
    if tuple(sorted(str(key) for key in seeds)) != tuple(sorted(_REQUIRED_SEEDS)):
        raise ValueError(f"{path}: expected PYTHONHASHSEED values {_REQUIRED_SEEDS}")
    digests: set[str] = set()
    for seed in _REQUIRED_SEEDS:
        result = seeds.get(seed)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ValueError(f"{path}: seed {seed} did not pass")
        digest = str(result.get("lifecycle_runtime_digest") or "")
        if len(digest) != 64:
            raise ValueError(f"{path}: seed {seed} missing lifecycle runtime digest")
        if int(result.get("tx_count") or 0) != 236:
            raise ValueError(f"{path}: seed {seed} did not execute 236 lifecycle vectors")
        digests.add(digest)
    if len(digests) != 1:
        raise ValueError(f"{path}: lifecycle digest changes across PYTHONHASHSEED values")


def build_transcript(
    packet_paths: list[Path],
    *,
    machine_isolation: str,
    operator_attestation: str,
    operator_signatures: list[str],
) -> Json:
    if len(packet_paths) < 2:
        raise ValueError("at least two machine packets are required")

    packets = [_read_packet(path) for path in packet_paths]
    for path, packet in zip(packet_paths, packets, strict=True):
        _require_packet(packet, path=path)

    machine_ids = [str(packet["machine_id"]) for packet in packets]
    if len(machine_ids) != len(set(machine_ids)):
        raise ValueError("machine_ids must be distinct")

    operator_ids = sorted({str(packet["operator_id"]) for packet in packets})
    commit = str(_one_value(packets, "commit"))
    git_tree = str(_one_value(packets, "git_tree"))
    state_root_vectors_sha256 = str(_one_value(packets, "state_root_vectors_sha256"))
    tx_lifecycle_assurance_sha256 = str(
        _one_value(packets, "tx_lifecycle_assurance_sha256")
    )
    tx_semantic_assurance_sha256 = str(_one_value(packets, "tx_semantic_assurance_sha256"))
    tx_contract_map_sha256 = str(_one_value(packets, "tx_contract_map_sha256"))
    broad_probe_lifecycle_manifest_sha256 = str(
        _one_value(packets, "broad_probe_lifecycle_manifest_sha256")
    )
    broad_probe_lifecycle_projection_sha256 = str(
        _one_value(packets, "broad_probe_lifecycle_projection_sha256")
    )
    broad_probe_reversed_projection_sha256 = str(
        _one_value(packets, "broad_probe_reversed_projection_sha256")
    )
    broad_probe_hash_seed_render_sha256 = _one_value(
        packets, "broad_probe_hash_seed_render_sha256"
    )

    if broad_probe_lifecycle_manifest_sha256 != tx_lifecycle_assurance_sha256:
        raise ValueError("broad probe lifecycle manifest digest does not match tracked lifecycle manifest")
    if broad_probe_lifecycle_projection_sha256 != broad_probe_reversed_projection_sha256:
        raise ValueError("broad probe insertion-order projection mismatch")

    # Same live-generated lifecycle digest across every seed on every machine.
    live_lifecycle_digests = {
        str(result["lifecycle_runtime_digest"])
        for packet in packets
        for result in packet["hashseed_results"].values()
    }
    if len(live_lifecycle_digests) != 1:
        raise ValueError("cross-machine live lifecycle digest mismatch")

    replay_digests = {str(packet["replay_manifest_digest"]) for packet in packets}
    db_replay_digests = {str(packet["db_replay_digest"]) for packet in packets}
    fresh_replay_digests = {str(packet["fresh_node_replay_digest"]) for packet in packets}
    state_roots = {str(packet["state_root"]) for packet in packets}
    fresh_state_roots = {str(packet["fresh_state_root"]) for packet in packets}
    tx_index_hashes = {str(packet["tx_index_sha256"]) for packet in packets}

    if len(replay_digests) != 1:
        raise ValueError("per-block replay manifest mismatch")
    if len(db_replay_digests) != 1:
        raise ValueError("DB-backed replay summary mismatch")
    if len(fresh_replay_digests) != 1:
        raise ValueError("fresh-node state-sync replay summary mismatch")
    if len(state_roots) != 1 or len(fresh_state_roots) != 1:
        raise ValueError("final state roots do not match across machines")
    if len(tx_index_hashes) != 1:
        raise ValueError("tx-index hash mismatch")

    branch_values = sorted({str(packet.get("branch") or "") for packet in packets})
    branch = branch_values[0] if len(branch_values) == 1 else "detached-or-mixed-branch"

    machine_summaries = {
        str(packet["machine_id"]): {
            "platform": str(packet.get("platform") or ""),
            "python": str(packet.get("python") or ""),
            "replay_consistency_ok": True,
            "fresh_node_replay_sync_ok": True,
            "db_backed_replay_sync_ok": True,
            "broad_lifecycle_corpus_ok": True,
            "scheduler_order_permutation_ok": True,
            "helper_serial_equivalence_ok": True,
            "failed_receipt_replay_ok": True,
            "hashseed_values": list(_REQUIRED_SEEDS),
            "lifecycle_runtime_digest": next(iter(live_lifecycle_digests)),
            "replay_manifest_digest": str(packet["replay_manifest_digest"]),
            "db_replay_digest": str(packet["db_replay_digest"]),
            "fresh_node_replay_digest": str(packet["fresh_node_replay_digest"]),
        }
        for packet in packets
    }

    tx_index_hash_by_machine = {
        str(packet["machine_id"]): str(packet["tx_index_sha256"]) for packet in packets
    }
    state_root_by_machine = {
        str(packet["machine_id"]): str(packet["state_root"]) for packet in packets
    }

    transcript: Json = {
        "schema": "weall.v1_5.external_cross_machine_replay_transcript",
        "blocker": "AUD-618-P1-003",
        "a04_f002_scope": True,
        "commit": commit,
        "git_tree": git_tree,
        "branch": branch,
        "operator_ids": operator_ids,
        "machine_ids": machine_ids,
        "machine_isolation": machine_isolation,
        "operator_attestation": operator_attestation,
        "external_attestation_attached": True,
        "machine_summaries": machine_summaries,
        "state_root_vectors_sha256": state_root_vectors_sha256,
        "tx_lifecycle_assurance_sha256": tx_lifecycle_assurance_sha256,
        "tx_semantic_assurance_sha256": tx_semantic_assurance_sha256,
        "tx_contract_map_sha256": tx_contract_map_sha256,
        "broad_probe_lifecycle_manifest_sha256": broad_probe_lifecycle_manifest_sha256,
        "broad_probe_lifecycle_projection_sha256": broad_probe_lifecycle_projection_sha256,
        "broad_probe_reversed_projection_sha256": broad_probe_reversed_projection_sha256,
        "broad_probe_hash_seed_render_sha256": broad_probe_hash_seed_render_sha256,
        "broad_probe_match": True,
        "insertion_order_projection_match": True,
        "live_lifecycle_digest": next(iter(live_lifecycle_digests)),
        "tx_index_hash_by_machine": tx_index_hash_by_machine,
        "state_root_by_machine": state_root_by_machine,
        "replay_manifest_digest_by_machine": {
            str(packet["machine_id"]): str(packet["replay_manifest_digest"])
            for packet in packets
        },
        "db_replay_digest_by_machine": {
            str(packet["machine_id"]): str(packet["db_replay_digest"]) for packet in packets
        },
        "fresh_node_replay_digest_by_machine": {
            str(packet["machine_id"]): str(packet["fresh_node_replay_digest"])
            for packet in packets
        },
        "hashseed_results_by_machine": {
            str(packet["machine_id"]): packet["hashseed_results"] for packet in packets
        },
        "replay_commands": [str(packet.get("capture_command") or "") for packet in packets],
        "replay_outputs": {
            str(packet["machine_id"]): str(path)
            for path, packet in zip(packet_paths, packets, strict=True)
        },
        "same_commit": True,
        "same_vectors": True,
        "state_roots_match": True,
        "tx_index_hash_match": True,
        "per_block_replay_match": True,
        "db_replay_match": True,
        "fresh_node_state_sync_match": True,
        "hashseed_matrix_match": True,
        "broad_transition_corpus": "all_236_canonical_lifecycle_vectors",
        "scheduler_order_permutation_vectors": True,
        "helper_serial_equivalence_vectors": True,
        "failed_receipt_replay_vectors": True,
        "external_machine_or_two_physical_machines": True,
        "operator_signatures": operator_signatures,
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "live_economics": False,
            "automatic_protocol_upgrades": False,
            "production_helper_execution": False,
            "legal_compliance_ready": False,
            "public_storage_provider_market": False,
        },
    }
    transcript["transcript_digest"] = _digest_without_self(transcript)
    return transcript


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the strict A04/external cross-machine replay aggregate transcript."
    )
    parser.add_argument("--packet", action="append", required=True, help="Local machine packet JSON")
    parser.add_argument(
        "--machine-isolation",
        required=True,
        choices=(
            "two_physical_machines",
            "external_machine_plus_isolated_founder_machine",
            "independent_machines",
        ),
    )
    parser.add_argument(
        "--operator-attestation",
        required=True,
        choices=("external_replay_operator_signed", "independent_operator_signed"),
    )
    parser.add_argument("--operator-signature", action="append", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    packet_paths = [Path(path).expanduser().resolve() for path in args.packet]
    transcript = build_transcript(
        packet_paths,
        machine_isolation=args.machine_isolation,
        operator_attestation=args.operator_attestation,
        operator_signatures=list(args.operator_signature),
    )
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(transcript, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote validated A04 aggregate transcript candidate: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
