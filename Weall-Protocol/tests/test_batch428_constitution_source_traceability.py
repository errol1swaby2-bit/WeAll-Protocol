from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSTITUTION = ROOT / "docs" / "constitution" / "WEALL_GENESIS_CONSTITUTION_DRAFT_2.md"
TRACEABILITY = ROOT / "docs" / "constitution" / "CONSTITUTIONAL_TRACEABILITY.md"


def test_genesis_constitution_draft_is_source_controlled() -> None:
    assert CONSTITUTION.exists(), "Genesis Constitution Draft 2 must be part of repo docs for recursive audits"
    text = CONSTITUTION.read_text(encoding="utf-8")

    required_phrases = [
        "draft: 2",
        "constitutional direct democracy",
        "Immutable Genesis Declaration",
        "Active Constitution",
        "No frontend, node operator, relay, helper service, indexer, storage provider, or private interface may become the final civic authority over users.",
        "No proposal, rule, group charter, moderation policy, role policy, algorithmic rule, treasury condition, or governance action may establish or promote civic supremacy",
        "Being verified as human does not automatically make a user a validator, juror, moderator, node operator, treasury signer, emissary, storage provider, or governance executor.",
        "Group-scoped posting, group treasury action, group moderation, and group governance must be controlled by protocol-recognized membership, roles, or permissions.",
        "Users should be able to connect through healthy nodes without being forced to operate personal infrastructure.",
    ]
    for phrase in required_phrases:
        assert phrase in text


def test_constitutional_traceability_maps_articles_to_protocol_surfaces() -> None:
    assert TRACEABILITY.exists(), "Constitutional traceability map must exist for recursive audit use"
    text = TRACEABILITY.read_text(encoding="utf-8")

    required_articles = [
        "Article I — Founding Status",
        "Article II — Core Rights",
        "Article III — Anti-Domination",
        "Article IV — Direct Democracy",
        "Article V — Proof of Humanity",
        "Article VI — Roles/Reputation",
        "Article VII — Disputes/Moderation",
        "Article VIII — Groups",
        "Article IX — Governance",
        "Article X — Nodes/Clients",
        "Article XI — Treasury/Economics",
        "Article XII — Emergency Powers",
        "Article XIII — Amendments",
        "Article XIV — Interpretation",
        "Article XV — Genesis Commitment",
    ]
    for article in required_articles:
        assert article in text

    required_surfaces = [
        "tx canon",
        "domain appliers",
        "PoH",
        "group-scoped posting",
        "healthy node manager",
        "treasury/economics activation",
        "constitutional amendment tx types",
    ]
    lowered = text.lower()
    for surface in required_surfaces:
        assert surface.lower() in lowered


def test_constitution_is_marked_draft_not_protocol_enforced_law() -> None:
    text = TRACEABILITY.read_text(encoding="utf-8")
    assert "not yet bound into genesis state by hash" in text
    assert "does not yet make the Constitution protocol-enforced genesis law" in text
