#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"m3_actor_builder_invalid_json:{label}:{path}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a schema-v3 M3 actor manifest from custody storage states and a signed transaction transcript.")
    parser.add_argument("--implementation-freeze", required=True)
    parser.add_argument("--backend-base-url", required=True)
    parser.add_argument("--frontend-base-url", default="http://127.0.0.1:5173")
    parser.add_argument("--actors-file", required=True, help="JSON list of {role, account, storage_state}; private key material is forbidden")
    parser.add_argument("--transaction-transcript", required=True)
    parser.add_argument("--post-id", required=True)
    parser.add_argument("--group-id", required=True)
    parser.add_argument("--group-post-id", required=True)
    parser.add_argument("--dispute-id", required=True)
    parser.add_argument("--proposal-id", required=True)
    parser.add_argument("--negative-post-id", required=True)
    parser.add_argument("--negative-group-id", required=True)
    parser.add_argument("--negative-dispute-id", required=True)
    parser.add_argument("--negative-proposal-id", required=True)
    parser.add_argument("--expected-dispute-stage", default="finalized")
    parser.add_argument("--expected-dispute-outcome", default="")
    parser.add_argument("--expected-proposal-stage", default="finalized")
    parser.add_argument("--minimum-final-ballots", type=int, default=1)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    try:
        freeze = subprocess.check_output(
            ["git", "rev-parse", f"{args.implementation_freeze}^{{commit}}"],
            cwd=ROOT,
            text=True,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise SystemExit("m3_actor_builder_freeze_commit_invalid") from exc

    actors_path = Path(args.actors_file).expanduser().resolve()
    transcript_path = Path(args.transaction_transcript).expanduser().resolve()
    actors = _load(actors_path, "actors")
    if not isinstance(actors, list) or not actors:
        raise SystemExit("m3_actor_builder_actors_not_list")
    for index, actor in enumerate(actors):
        if not isinstance(actor, dict):
            raise SystemExit(f"m3_actor_builder_actor_not_object:{index}")
        if set(actor) != {"role", "account", "storage_state"}:
            raise SystemExit(f"m3_actor_builder_actor_keys_invalid:{index}")
        storage = Path(str(actor["storage_state"])).expanduser().resolve()
        if not storage.is_file() or storage.is_symlink():
            raise SystemExit(f"m3_actor_builder_storage_missing:{storage}")
        actor["storage_state"] = str(storage)
    transcript = _load(transcript_path, "transcript")
    if not isinstance(transcript, dict) or transcript.get("schema_version") != 1:
        raise SystemExit("m3_actor_builder_transcript_schema_invalid")
    if str(transcript.get("implementation_freeze_commit") or "") != freeze:
        raise SystemExit("m3_actor_builder_transcript_freeze_mismatch")

    journey: dict[str, Any] = {
        "post_id": args.post_id,
        "group_id": args.group_id,
        "group_post_id": args.group_post_id,
        "dispute_id": args.dispute_id,
        "proposal_id": args.proposal_id,
        "negative_post_id": args.negative_post_id,
        "negative_group_id": args.negative_group_id,
        "negative_dispute_id": args.negative_dispute_id,
        "negative_proposal_id": args.negative_proposal_id,
        "transaction_transcript": str(transcript_path),
        "expected_dispute_stage": args.expected_dispute_stage,
        "expected_proposal_stage": args.expected_proposal_stage,
        "minimum_final_ballots": max(1, int(args.minimum_final_ballots)),
    }
    if args.expected_dispute_outcome:
        journey["expected_dispute_outcome"] = args.expected_dispute_outcome

    manifest = {
        "schema_version": 3,
        "implementation_freeze_commit": freeze,
        "backend_base_url": str(args.backend_base_url).rstrip("/"),
        "frontend_base_url": str(args.frontend_base_url).rstrip("/"),
        "actors": actors,
        "journey": journey,
    }
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
