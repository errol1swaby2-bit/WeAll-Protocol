from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "src"


def read(rel: str) -> str:
    return (WEB / rel).read_text(encoding="utf-8")


def test_messages_page_is_wired_to_messaging_state_and_send_tx() -> None:
    text = read("pages/Messaging.tsx")
    assert "weall.messageThreads" in text
    assert "weall.messageThread" in text
    assert "getAuthHeaders" in text
    assert "weall.stateSnapshot(apiBase)" not in text
    assert "DIRECT_MESSAGE_SEND" in text
    assert "Send message" in text
    assert "Conversations" in text
    assert "Message myself for demo" in text


def test_decisions_page_defaults_to_all_and_shows_outcomes() -> None:
    text = read("pages/Proposals.tsx")
    assert 'useState<"active" | "all">("all")' in text
    assert "decisionOutcomeLabel" in text
    assert "decisionOutcomeText" in text
    assert "open votes only" in text
    assert "Final result" in text
    assert "Outcome" in text


def test_reviews_page_prioritizes_assigned_flagged_content() -> None:
    text = read("pages/JurorDashboard.tsx")
    assert "Review assigned community work" in text
    assert "Assigned content reviews" in text
    assert "weall.disputes" in text
    assert "weall.content" in text
    assert "Content preview" in text
    assert "Open review workspace" in text
    # The content-review section should appear before the account verification queue section.
    assert text.index("Assigned content reviews") < text.index("Assigned async verification reviews")
