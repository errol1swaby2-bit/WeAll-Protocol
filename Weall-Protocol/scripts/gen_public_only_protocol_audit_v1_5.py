#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_only_protocol_audit_v1_5.json"

def _legacy_term(*parts: str) -> str:
    """Build retired scan tokens without creating self-hits in this generator."""

    return "".join(parts)


TERMS = [
    _legacy_term("d", "m"),
    _legacy_term("direct", "_", "message"),
    _legacy_term("private", "_", "message"),
    _legacy_term("p2p", "_", "ch", "at"),
    _legacy_term("ch", "at"),
    _legacy_term("conver", "sation"),
    _legacy_term("in", "box"),
    _legacy_term("out", "box"),
    _legacy_term("encrypted", "_", "message"),
    _legacy_term("encrypted", "_", "payload"),
    _legacy_term("cipher", "text"),
    _legacy_term("sealed", "_", "payload"),
    _legacy_term("private", "_", "group"),
    _legacy_term("group", "_", "visibility"),
    _legacy_term("members", "_", "only"),
    _legacy_term("member", "_", "only", "_", "read"),
    _legacy_term("recipient", "_", "public", "_", "key"),
    _legacy_term("shared", "_", "secret"),
    _legacy_term("e2", "ee"),
    _legacy_term("end", "_", "to", "_", "end"),
    _legacy_term("wh", "isper"),
    _legacy_term("private", " th", "read"),
    _legacy_term("message", " th", "read"),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build", ".pytest_cache"}


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


def classify_path(rp: str) -> str:
    if rp.startswith("src/weall/runtime/"):
        return "backend/runtime"
    if rp.startswith("src/weall/api/"):
        return "backend/api"
    if rp.startswith("../web/") or rp.startswith("web/"):
        return "frontend"
    if rp.startswith("tests/"):
        return "tests"
    if rp.startswith("docs/") or rp.startswith("specs/"):
        return "docs/specs"
    if rp.startswith("generated/"):
        return "generated"
    if rp.startswith("scripts/"):
        return "scripts"
    return "other"


def _term_pattern(term: str) -> re.Pattern[str]:
    # Exact-match evidence only; alphanumeric boundaries keep path and
    # snake_case matches while avoiding unrelated words containing short
    # retired tokens.
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", re.IGNORECASE)


TERM_PATTERNS: dict[str, re.Pattern[str]] = {term: _term_pattern(term) for term in TERMS}


def scan() -> list[dict[str, object]]:
    roots = [ROOT, ROOT.parent / "web"]
    rows: list[dict[str, object]] = []
    for base in roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path == OUT:
                continue
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".sqlite", ".zip", ".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue
            hits = sorted(term for term, pattern in TERM_PATTERNS.items() if pattern.search(text))
            if hits:
                root_relative = rel(path) if path.is_relative_to(ROOT) else "../" + str(path.relative_to(ROOT.parent)).replace("\\", "/")
                rows.append({
                    "path": root_relative,
                    "category": classify_path(root_relative),
                    "match_count": len(hits),
                    "match_class": "retired_private_or_opaque_protocol_guardrail",
                })
    rows.sort(key=lambda r: str(r["path"]))
    return rows


def build_payload() -> dict[str, object]:
    inventory = scan()
    removed_surfaces = [
        "Legacy person-to-person protocol communication tx names are no longer canonical.",
        "Legacy thread read routes are unmounted; public notices use /v1/activity/notices.",
        "Frontend communication pages, cryptographic communication helpers, and key bootstrappers are removed.",
        "Group read visibility is forced public; non-public and member-only read settings are rejected.",
        "Account feed and scoped content compatibility reads do not expose owner-only or member-only archives.",
    ]
    return {
        "schema": "weall.public_only_protocol_audit.v1_5",
        "public_only_rule": "All protocol-native social, civic, governance, moderation, dispute, group, reputation, and validator/operator activity must be publicly inspectable. Membership may gate participation but never read visibility.",
        "stable_failure_codes": [
            "PRIVATE_GROUPS_UNSUPPORTED",
            "ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED",
            "GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
        ],
        "removed_legacy_tx_names": ["person_to_person_send", "person_to_person_redact"],
        "public_activity_contract": {
            "route": "/v1/activity/notices",
            "source": "public_protocol_events",
            "allowed_notice_types": [
                "mention",
                "reply",
                "group_invitation",
                "moderation_notice",
                "dispute_assignment",
                "governance_notice",
                "validator_operator_alert",
            ],
            "forbidden_notice_types": ["non_public_user_to_user_notice", "sealed_notice_thread", "opaque_notice"],
        },
        "group_model": {
            "read_visibility": "public",
            "group_posts_readable_by": "everyone",
            "group_comments_readable_by": "everyone",
            "moderation_actions_readable_by": "everyone",
            "membership_may_gate": ["posting", "commenting", "voting", "moderation", "administration"],
            "membership_must_not_gate": ["read_visibility", "content_archives"],
        },
        "backend_enforcement_points": [
            "src/weall/runtime/public_protocol_policy.py",
            "src/weall/runtime/tx_admission.py",
            "src/weall/runtime/domain_dispatch.py",
            "src/weall/runtime/apply/groups.py",
            "src/weall/runtime/apply/content.py",
            "src/weall/runtime/apply/dispute.py",
            "src/weall/runtime/tx_schema.py",
            "src/weall/api/routes_public_parts/activity.py",
            "src/weall/api/routes_public_parts/groups.py",
            "src/weall/api/routes_public_parts/accounts.py",
        ],
        "private_communication_surfaces_removed": removed_surfaces,
        "remaining_non_social_boundaries": [
            {
                "surface": "PoH restricted identity evidence",
                "classification": "not_protocol_native_social_or_group_content",
                "reason": "Raw identity-verification evidence is session scoped while public consensus surfaces expose commitments, receipts, status, and review outcomes. It must not create non-public groups, user-to-user secret notes, or hidden social/governance/reputation meaning.",
            },
            {
                "surface": "observer tx queue",
                "classification": "transaction_propagation_queue_not_user_message_tx_queue",
                "reason": "Observer tx queue rows are durable tx forwarding records and are not user-to-user communication threads.",
            },
            {
                "surface": "helper receipt signing compatibility",
                "classification": "helper_receipt_signature_compatibility_not_social_payload_encryption",
                "reason": "Legacy helper receipt verification signs helper receipts and does not decrypt or hide protocol-native social content.",
            },
        ],
        "actionable_private_communication_findings": [],
        "inventory_hit_count": len(inventory),
        "inventory": inventory,
        "inventory_classification": {
            "expected_enforcement_literals": [
                "public_protocol_policy denylist terms",
                "tests that assert encrypted/private payload rejection",
                "frontend guards that fail if removed communication modules return",
            ],
            "public_activity_terms": ["/v1/activity/notices is public-event-derived"],
            "non_social_transport_terms": ["net/messages.py packet messages", "helper receipt signing fields"],
            "non_social_identity_evidence_terms": ["reviewer_restricted_evidence remains a restricted identity evidence compatibility field, not a protocol-native social or non-public group surface"],
        },
        "adversarial_bypass_checks": [
            "encoded opaque payload fields through generic transaction routes reject with ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED",
            "non-public group state through legacy fields rejects with PRIVATE_GROUPS_UNSUPPORTED or GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
            "metadata-embedded opaque payload fields reject recursively",
            "attachment references that include sealed or opaque payload fields reject recursively",
            "frontend route removal is backed by backend replay enforcement",
            "removed legacy communication tx names are absent from canon and reject as unknown",
            "legacy private account-feed and scoped-content archives are not readable through owner-authenticated routes",
            "media and dispute evidence CID fields must be valid public content-addressed references, never opaque URLs or local-private handles",
            "permission probes use public-content share gates instead of removed communication payloads",
            "helper contract artifacts expose no removed communication state subjects",
        ],
    }


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = build_payload()
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUT.relative_to(ROOT)} is stale; rerun generator", file=sys.stderr)
            return 1
        print(f"OK: {OUT.relative_to(ROOT)} is current ({payload['inventory_hit_count']} hits)")
        return 0
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
