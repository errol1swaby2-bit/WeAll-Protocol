#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_only_protocol_audit_v1_5.json"

TERMS = [
    "dm",
    "direct_message",
    "private_message",
    "p2p_chat",
    "chat",
    "conversation",
    "inbox",
    "outbox",
    "encrypted_message",
    "encrypted_payload",
    "ciphertext",
    "sealed_payload",
    "private_group",
    "group_visibility",
    "members_only",
    "member_only_read",
    "recipient_public_key",
    "shared_secret",
    "e2ee",
    "end_to_end",
    "whisper",
    "private thread",
    "message thread",
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


def scan() -> list[dict[str, object]]:
    pattern = re.compile("|".join(re.escape(t) for t in TERMS), re.IGNORECASE)
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
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".sqlite", ".zip", ".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue
            hits = sorted({m.group(0).lower() for m in pattern.finditer(text)})
            if hits:
                root_relative = rel(path) if path.is_relative_to(ROOT) else "../" + str(path.relative_to(ROOT.parent)).replace("\\", "/")
                rows.append({"path": root_relative, "category": classify_path(root_relative), "terms": hits})
    rows.sort(key=lambda r: str(r["path"]))
    return rows


def build_payload() -> dict[str, object]:
    inventory = scan()
    private_communication_surfaces_removed = [
        "DIRECT_MESSAGE_SEND and DIRECT_MESSAGE_REDACT are rejected at mempool admission and apply/replay with PRIVATE_MESSAGING_UNSUPPORTED.",
        "/v1/messages/threads and /v1/messages/threads/{thread_id} are compatibility stubs returning PRIVATE_MESSAGING_UNSUPPORTED.",
        "Frontend /messages routes and navigation entries are removed and replaced by /activity.",
        "Client-side messaging key bootstrap and account-registration messaging-encryption key publication are disabled.",
        "Group read visibility is forced public; private, members-only, scoped, closed, and member-only read settings are rejected.",
        "Account feed and scoped content compatibility reads no longer expose owner-only or member-only private archives.",
    ]
    return {
        "schema": "weall.public_only_protocol_audit.v1_5",
        "public_only_rule": "All protocol-native social, civic, governance, moderation, dispute, group, reputation, and validator/operator activity must be publicly inspectable. Membership may gate participation but never read visibility.",
        "stable_failure_codes": [
            "PRIVATE_MESSAGING_UNSUPPORTED",
            "PRIVATE_GROUPS_UNSUPPORTED",
            "ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED",
            "GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
        ],
        "unsupported_legacy_tx_types": ["DIRECT_MESSAGE_SEND", "DIRECT_MESSAGE_REDACT"],
        "public_activity_contract": {
            "route": "/v1/activity/inbox",
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
            "forbidden_notice_types": ["direct_message", "private_thread", "encrypted_conversation"],
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
            "src/weall/api/routes_public_parts/messages.py",
            "src/weall/api/routes_public_parts/groups.py",
            "src/weall/api/routes_public_parts/accounts.py",
        ],
        "private_communication_surfaces_removed": private_communication_surfaces_removed,
        "inventory_hit_count": len(inventory),
        "inventory": inventory,
        "adversarial_bypass_checks": [
            "encrypted payloads through generic transaction routes reject with ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED",
            "private group state through legacy fields rejects with PRIVATE_GROUPS_UNSUPPORTED or GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
            "metadata-embedded sealed/ciphertext payloads reject recursively",
            "attachment references that include ciphertext/sealed payload fields reject recursively",
            "frontend route removal is backed by backend replay enforcement",
            "legacy DIRECT_MESSAGE_* fixtures reject before schema/domain apply",
            "legacy private account-feed and scoped-content archives are not readable through owner-authenticated routes",
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
