from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .errors import ClosureToolingError
from .http_client import RateLimitedJsonClient, RetryPolicy
from .models import (
    EvidenceKind,
    InlineSystemTransitionAction,
    parse_transcript,
)
from .receipts import ReceiptStore
from .replay_status import load_replay_status_config, run_replay_status
from .util import atomic_write_json
from .verification import verify_transcript_statuses


def _validate_transcript(args: argparse.Namespace) -> int:
    transcript = parse_transcript(args.transcript)
    counts = {kind.value: 0 for kind in EvidenceKind}
    for action in transcript.actions:
        counts[action.evidence_kind.value] += 1

    inline = [
        action
        for action in transcript.actions
        if isinstance(action, InlineSystemTransitionAction)
    ]
    payload = {
        "schema": "weall.m3.transcript-validation.v2",
        "source": str(Path(args.transcript).resolve()),
        "source_sha256": transcript.source_sha256,
        "fingerprint": transcript.fingerprint,
        "implementation_freeze_commit": transcript.implementation_freeze_commit,
        "chain_id": transcript.chain_id,
        "action_count": len(transcript.actions),
        "negative_attempt_count": len(transcript.negative_attempts),
        "evidence_kind_counts": counts,
        "inline_actions": [
            {
                "index": action.index,
                "label": action.label,
                "tx_type": action.tx_type,
                "tx_id": action.tx_id,
                "trigger_tx_id": action.trigger_tx_id,
                "trigger_included_height": action.trigger_included_height,
                "state_height": action.state_height,
            }
            for action in inline
        ],
        "ok": True,
    }
    if args.out:
        atomic_write_json(args.out, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _verify_status(args: argparse.Namespace) -> int:
    transcript = parse_transcript(args.transcript)
    client = RateLimitedJsonClient(
        args.api_base,
        policy=RetryPolicy(
            max_attempts=args.max_attempts,
            base_delay_s=args.base_delay,
            max_delay_s=args.max_delay,
            minimum_interval_s=args.minimum_interval,
            timeout_s=args.timeout,
        ),
    )
    summary = verify_transcript_statuses(transcript, client)
    payload = summary.to_json()
    payload["transcript_fingerprint"] = transcript.fingerprint
    payload["api_base"] = args.api_base.rstrip("/")
    atomic_write_json(args.out, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _inspect_receipt(args: argparse.Namespace) -> int:
    receipt = ReceiptStore(args.receipt_root).load(args.stage)
    print(json.dumps(receipt.to_json(), indent=2, sort_keys=True))
    return 0


def _verify_replay_status(args: argparse.Namespace) -> int:
    config = load_replay_status_config(args.config)
    payload = run_replay_status(config)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m3-closure-v2",
        description="Typed, resumable WeAll M3 closure tooling.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="m3-closure-v2 0.1.0",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser(
        "validate-transcript",
        help="Validate and classify an M3 transaction transcript.",
    )
    validate.add_argument("--transcript", required=True)
    validate.add_argument("--out")
    validate.set_defaults(handler=_validate_transcript)

    verify = sub.add_parser(
        "verify-status",
        help="Verify typed transcript actions through a live API.",
    )
    verify.add_argument("--api-base", required=True)
    verify.add_argument("--transcript", required=True)
    verify.add_argument("--out", required=True)
    verify.add_argument("--max-attempts", type=int, default=8)
    verify.add_argument("--base-delay", type=float, default=0.5)
    verify.add_argument("--max-delay", type=float, default=30.0)
    verify.add_argument("--minimum-interval", type=float, default=0.15)
    verify.add_argument("--timeout", type=float, default=15.0)
    verify.set_defaults(handler=_verify_status)

    receipt = sub.add_parser(
        "inspect-receipt",
        help="Load and verify a stage receipt and its own hash.",
    )
    receipt.add_argument("--receipt-root", required=True)
    receipt.add_argument("--stage", required=True)
    receipt.set_defaults(handler=_inspect_receipt)

    replay = sub.add_parser(
        "verify-replay-status",
        help=(
            "Create a fresh private ledger snapshot, start an owned current-"
            "freeze backend, and verify the canonical transcript with bounded "
            "rate-limit handling."
        ),
    )
    replay.add_argument("--config", required=True)
    replay.set_defaults(handler=_verify_replay_status)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except ClosureToolingError as exc:
        print(f"M3_CLOSURE_V2_ERROR:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
