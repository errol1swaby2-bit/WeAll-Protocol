from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = ROOT.parent

PRIVATE_TERMS = (
    "DIRECT_MESSAGE_SEND",
    "DIRECT_MESSAGE_REDACT",
    "direct_message",
    "private_message",
    "p2p_chat",
    "encrypted_message",
    "encrypted_payload",
    "ciphertext",
    "sealed_payload",
)

ACTIVE_CLAIM_PATTERNS = (
    r"supports\s+private\s+messaging",
    r"encrypted\s+direct\s+messages\s+are\s+supported",
    r"private\s+groups\s+are\s+supported",
    r"member[- ]only\s+read\s+access\s+is\s+supported",
)


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected file: {path}"
    return path.read_text(encoding="utf-8")


def test_direct_message_tx_types_absent_from_public_testnet_tx_index() -> None:
    payload = json.loads(_read(ROOT / "generated" / "tx_index.json"))
    by_name = payload.get("by_name", {})
    tx_types = payload.get("tx_types", [])
    names = set(by_name)
    names.update(str(row.get("name", "")) for row in tx_types if isinstance(row, dict))

    assert "DIRECT_MESSAGE_SEND" not in names
    assert "DIRECT_MESSAGE_REDACT" not in names
    assert not [name for name in names if "DIRECT_MESSAGE" in name or "PRIVATE_MESSAGE" in name or "P2P_CHAT" in name]


def test_tx_canon_source_does_not_regenerate_private_message_types() -> None:
    canon = _read(ROOT / "specs" / "tx_canon" / "tx_canon.yaml")
    schema = _read(ROOT / "src" / "weall" / "runtime" / "tx_schema.py")
    generated = _read(ROOT / "generated" / "tx_index.json")

    combined = "\n".join([canon, schema, generated])
    for term in PRIVATE_TERMS:
        assert term not in combined, f"private/direct message tx term must stay absent from canon/schema/generated artifacts: {term}"


def test_reviewer_docs_quarantine_private_message_language_instead_of_claiming_it() -> None:
    docs = [
        OUTER_ROOT / "README.md",
        ROOT / "docs" / "reviewer" / "DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md",
        ROOT / "docs" / "PUBLIC_ONLY_PROTOCOL.md",
        ROOT / "docs" / "ARCHITECTURE_DECISIONS" / "0002-remove-protocol-native-private-messaging.md",
    ]
    combined = "\n".join(_read(path) for path in docs).lower()

    for required in (
        "public-only civic protocol",
        "private/direct/encrypted messaging is not part of the nlnet/public-testnet claim",
        "legacy/out-of-scope",
        "group membership may gate",
        "must not gate read visibility",
    ):
        assert required in combined

    for pattern in ACTIVE_CLAIM_PATTERNS:
        assert re.search(pattern, combined, flags=re.I) is None, f"active private messaging/group claim found: {pattern}"


def test_group_public_only_contract_keeps_private_group_read_support_false() -> None:
    route = _read(ROOT / "src" / "weall" / "api" / "routes_public_parts" / "groups.py")
    api = _read(OUTER_ROOT / "web" / "src" / "api" / "weall.ts")

    assert '"private_groups_supported": False' in route
    assert '"member_only_read_supported": False' in route
    assert "private_groups_supported?: boolean" in api
    assert "member_only_read_supported?: boolean" in api
