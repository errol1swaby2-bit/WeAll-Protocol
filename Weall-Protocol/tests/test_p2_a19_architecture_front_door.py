from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARCH = ROOT / "Weall-Protocol" / "docs" / "ARCHITECTURE.md"


def test_current_architecture_map_is_linked_from_repository_front_door() -> None:
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Weall-Protocol/docs/ARCHITECTURE.md" in root_readme

    text = ARCH.read_text(encoding="utf-8")
    for heading in (
        "## Authority hierarchy",
        "## Runtime component map",
        "## Transaction lifecycle",
        "## Consensus and block authority",
        "## Persistence and restart boundary",
        "## PoH boundary",
        "## Governance, treasury, and economics",
        "## Helper execution boundary",
        "## P2P and trust boundaries",
        "## API and frontend authority boundary",
        "## Current versus target specification hierarchy",
        "## Disabled or launch-gated surfaces",
        "## Legacy and shadow material",
    ):
        assert heading in text
