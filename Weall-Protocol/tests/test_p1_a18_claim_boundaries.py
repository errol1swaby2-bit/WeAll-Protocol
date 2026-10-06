from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_a18_f004_readme_colocates_poh_status_with_uniqueness_boundary() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    marker = "Proof-of-Humanity checkpoint:"
    assert marker in text

    paragraph = text.split(marker, 1)[1].split("\n\n", 1)[0]
    assert "Tier 1 = native async review (compatibility/rehearsal state)" in paragraph
    assert "Tier 2 = native live review (compatibility/rehearsal state)" in paragraph
    assert "scope_closed_pending_uniqueness_entropy" in paragraph
    assert "These tiers are not proof of global one-human uniqueness." in paragraph


def test_a18_f004_readme_does_not_reintroduce_verified_human_shorthand_at_checkpoint() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    paragraph = text.split("Proof-of-Humanity checkpoint:", 1)[1].split("\n\n", 1)[0]
    lowered = paragraph.lower()

    assert "verified human" not in lowered
    assert "one-human uniqueness" in lowered
