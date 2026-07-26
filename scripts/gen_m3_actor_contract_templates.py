#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from m3_evidence_contract import (
    ACTION_MIN_COUNTS,
    ACTION_TX_TYPES,
    APPEAL_REVIEWER_ROLE_PREFIX,
    EMBEDDED_ATTENDANCE_EVIDENCE_KIND,
    EMBEDDED_ATTENDANCE_LABELS,
    ATTENDANCE_ACCEPTANCE_LABEL,
    EXPECTED_NEGATIVE_ERROR_CODES,
    MAIN_ACTION_SUBJECT_FIELD,
    NEGATIVE_TX_TYPES,
    ORIGINAL_REVIEWER_ROLE_PREFIX,
    REQUIRED_ACTION_LABELS,
    SYSTEM_ACTION_LABELS,
)

ROOT = Path(__file__).resolve().parents[1]


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _actor_for(label: str, index: int) -> tuple[str, str]:
    if label in SYSTEM_ACTION_LABELS:
        return "system_scheduler", "SYSTEM"
    if label.startswith("original_panel_"):
        role = f"{ORIGINAL_REVIEWER_ROLE_PREFIX}{index:02d}"
        return role, f"@m3_original_{index:02d}"
    if label.startswith("appeal_panel_"):
        role = f"{APPEAL_REVIEWER_ROLE_PREFIX}{index:02d}"
        return role, f"@m3_appeal_{index:02d}"
    if label in {"membership_request", "group_post_create", "content_report", "appeal_open", "proposal_comment"}:
        return "member_reporter_voter", "@m3_member"
    if label == "eligible_ballots" and index == 2:
        return "member_reporter_voter", "@m3_member"
    return "author_proposer", "@m3_author"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate fillable M3 actor and transaction-transcript templates.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--implementation-freeze", default="HEAD")
    parser.add_argument("--post-id", default="post:m3:main")
    parser.add_argument("--group-id", default="group:m3:main")
    parser.add_argument("--group-post-id", default="post:m3:group-main")
    parser.add_argument("--dispute-id", default="dispute:m3:main")
    parser.add_argument("--proposal-id", default="proposal:m3:main")
    parser.add_argument("--negative-post-id", default="post:m3:negative")
    parser.add_argument("--negative-group-id", default="group:m3:negative")
    parser.add_argument("--negative-dispute-id", default="dispute:m3:negative")
    parser.add_argument("--negative-proposal-id", default="proposal:m3:negative")
    args = parser.parse_args()

    try:
        freeze = subprocess.check_output(
            ["git", "rev-parse", f"{args.implementation_freeze}^{{commit}}"],
            cwd=ROOT,
            text=True,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise SystemExit("m3_template_freeze_commit_invalid") from exc

    out_dir = Path(args.out_dir).expanduser().resolve()
    journey = {
        "post_id": args.post_id,
        "group_id": args.group_id,
        "group_post_id": args.group_post_id,
        "dispute_id": args.dispute_id,
        "proposal_id": args.proposal_id,
        "negative_post_id": args.negative_post_id,
        "negative_group_id": args.negative_group_id,
        "negative_dispute_id": args.negative_dispute_id,
        "negative_proposal_id": args.negative_proposal_id,
    }

    actors = [
        {
            "role": "author_proposer",
            "account": "@m3_author",
            "storage_state": str(out_dir / "storage" / "author.json"),
            "signer_state": str(out_dir / "signers" / "author.signer.json"),
        },
        {
            "role": "member_reporter_voter",
            "account": "@m3_member",
            "storage_state": str(out_dir / "storage" / "member.json"),
            "signer_state": str(out_dir / "signers" / "member.signer.json"),
        },
        {
            "role": "nonmember_ineligible",
            "account": "@m3_outsider",
            "storage_state": str(out_dir / "storage" / "outsider.json"),
            "signer_state": str(out_dir / "signers" / "outsider.signer.json"),
        },
    ]
    actors.extend(
        {
            "role": f"{ORIGINAL_REVIEWER_ROLE_PREFIX}{index:02d}",
            "account": f"@m3_original_{index:02d}",
            "storage_state": str(out_dir / "storage" / f"original-{index:02d}.json"),
            "signer_state": str(out_dir / "signers" / f"original-{index:02d}.signer.json"),
        }
        for index in range(1, 10)
    )
    actors.extend(
        {
            "role": f"{APPEAL_REVIEWER_ROLE_PREFIX}{index:02d}",
            "account": f"@m3_appeal_{index:02d}",
            "storage_state": str(out_dir / "storage" / f"appeal-{index:02d}.json"),
            "signer_state": str(out_dir / "signers" / f"appeal-{index:02d}.signer.json"),
        }
        for index in range(1, 10)
    )

    actions: list[dict] = []
    serial = 0
    for label in sorted(REQUIRED_ACTION_LABELS):
        for index in range(1, ACTION_MIN_COUNTS[label] + 1):
            serial += 1
            role, account = _actor_for(label, index)
            actions.append(
                {
                    "label": label,
                    "role": role,
                    "account": account,
                    "tx_type": sorted(ACTION_TX_TYPES[label])[0],
                    "tx_id": f"REPLACE_CONFIRMED_TX_{serial:03d}",
                    "subject_id": journey[MAIN_ACTION_SUBJECT_FIELD[label]],
                    "status": "confirmed",
                }
            )

    extras = [
        ("post_create", "author_proposer", "@m3_author", "CONTENT_POST_CREATE", journey["negative_post_id"], "negative-post"),
        ("group_create", "author_proposer", "@m3_author", "GROUP_CREATE", journey["negative_group_id"], "negative-group"),
        ("content_report", "member_reporter_voter", "@m3_member", "CONTENT_FLAG", journey["negative_post_id"], "negative-report"),
        ("proposal_create", "author_proposer", "@m3_author", "GOV_PROPOSAL_CREATE", journey["negative_proposal_id"], "negative-proposal"),
        ("eligible_ballots", "member_reporter_voter", "@m3_member", "GOV_VOTE_CAST", journey["negative_proposal_id"], "negative-governance-vote"),
        ("original_panel_acceptance", f"{ORIGINAL_REVIEWER_ROLE_PREFIX}01", "@m3_original_01", "DISPUTE_JUROR_ACCEPT", journey["negative_dispute_id"], "negative-dispute-accept"),
        ("original_panel_attendance", f"{ORIGINAL_REVIEWER_ROLE_PREFIX}01", "@m3_original_01", "DISPUTE_JUROR_ATTENDANCE", journey["negative_dispute_id"], "negative-dispute-attendance"),
        ("original_panel_ballots", f"{ORIGINAL_REVIEWER_ROLE_PREFIX}01", "@m3_original_01", "DISPUTE_VOTE_SUBMIT", journey["negative_dispute_id"], "negative-dispute-vote"),
    ]
    for label, role, account, tx_type, subject, suffix in extras:
        actions.append(
            {
                "label": label,
                "role": role,
                "account": account,
                "tx_type": tx_type,
                "tx_id": f"REPLACE_CONFIRMED_{suffix.upper().replace('-', '_')}",
                "subject_id": subject,
                "status": "confirmed",
            }
        )

    for attendance in actions:
        attendance_label = str(attendance.get("label") or "")
        if attendance_label not in EMBEDDED_ATTENDANCE_LABELS:
            continue
        acceptance_label = ATTENDANCE_ACCEPTANCE_LABEL[attendance_label]
        matches = [
            item
            for item in actions
            if item.get("label") == acceptance_label
            and item.get("role") == attendance.get("role")
            and item.get("account") == attendance.get("account")
            and item.get("subject_id") == attendance.get("subject_id")
        ]
        if len(matches) != 1:
            raise SystemExit(
                f"m3_template_attendance_acceptance_pair_invalid:{attendance_label}"
            )
        attendance["tx_type"] = "DISPUTE_JUROR_ACCEPT"
        attendance["tx_id"] = matches[0]["tx_id"]
        attendance["evidence_kind"] = EMBEDDED_ATTENDANCE_EVIDENCE_KIND

    def negative(label: str, role: str, account: str, subject: str, payload: dict, prior: str = "") -> dict:
        value = {
            "label": label,
            "role": role,
            "account": account,
            "tx_type": sorted(NEGATIVE_TX_TYPES[label])[0],
            "payload": payload,
            "subject_id": subject,
            "expected_error_code": EXPECTED_NEGATIVE_ERROR_CODES[label],
        }
        if prior:
            value["precondition_tx_id"] = prior
        return value

    negatives = [
        negative(
            "nonmember_group_write_rejected",
            "nonmember_ineligible",
            "@m3_outsider",
            journey["negative_group_id"],
            {"post_id": "post:m3:forbidden", "body": "must fail", "group_id": journey["negative_group_id"]},
        ),
        negative(
            "nonselected_reviewer_vote_rejected",
            f"{APPEAL_REVIEWER_ROLE_PREFIX}01",
            "@m3_appeal_01",
            journey["negative_dispute_id"],
            {"dispute_id": journey["negative_dispute_id"], "vote": "yes"},
        ),
        negative(
            "conflicted_reviewer_vote_rejected",
            "author_proposer",
            "@m3_author",
            journey["negative_dispute_id"],
            {"dispute_id": journey["negative_dispute_id"], "vote": "yes"},
        ),
        negative(
            "ineligible_governance_vote_rejected",
            "nonmember_ineligible",
            "@m3_outsider",
            journey["negative_proposal_id"],
            {"proposal_id": journey["negative_proposal_id"], "vote": "yes"},
        ),
    ]
    for label in ("duplicate_governance_vote_rejected", "replacement_governance_vote_rejected", "governance_revoke_rejected"):
        negatives.append(
            negative(
                label,
                "member_reporter_voter",
                "@m3_member",
                journey["negative_proposal_id"],
                {"proposal_id": journey["negative_proposal_id"], **({} if "revoke" in label else {"vote": "no"})},
                "REPLACE_CONFIRMED_NEGATIVE_GOVERNANCE_VOTE",
            )
        )
    for label in ("duplicate_dispute_ballot_rejected", "replacement_dispute_ballot_rejected", "dispute_revoke_rejected"):
        negatives.append(
            negative(
                label,
                f"{ORIGINAL_REVIEWER_ROLE_PREFIX}01",
                "@m3_original_01",
                journey["negative_dispute_id"],
                {"dispute_id": journey["negative_dispute_id"], **({} if "revoke" in label else {"vote": "no"})},
                "REPLACE_CONFIRMED_NEGATIVE_DISPUTE_VOTE",
            )
        )

    transcript = {
        "schema_version": 1,
        "implementation_freeze_commit": freeze,
        "chain_id": "REPLACE_WITH_LIVE_CHAIN_ID",
        "actions": actions,
        "negative_attempts": negatives,
        "template_notice": "Replace every REPLACE_* value with evidence from the live signed journey before validation.",
    }
    actor_manifest_seed = {
        "schema_version": 3,
        "implementation_freeze_commit": freeze,
        "backend_base_url": "http://127.0.0.1:18401",
        "frontend_base_url": "http://127.0.0.1:5173",
        "actors": actors,
        "journey": {
            **journey,
            "transaction_transcript": str(out_dir / "m3-transaction-transcript.template.json"),
            "expected_dispute_stage": "finalized",
            "expected_proposal_stage": "finalized",
            "minimum_final_ballots": 2,
        },
        "template_notice": "Create each actor through the real custody flow, then populate storage_state and private signer_state paths before building the final manifest.",
    }

    _write(out_dir / "m3-actors.template.json", actors)
    _write(out_dir / "m3-transaction-transcript.template.json", transcript)
    _write(out_dir / "M3_ACTOR_MANIFEST.template.json", actor_manifest_seed)
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
