from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_PAGE = ROOT / "web" / "src" / "pages" / "Account.tsx"
ONBOARDING = ROOT / "web" / "src" / "lib" / "onboarding.ts"
CREATE_POST_PAGE = ROOT / "web" / "src" / "pages" / "CreatePostPage.tsx"


def test_profile_posting_gate_matches_protocol_live_verification_gate() -> None:
    src = ACCOUNT_PAGE.read_text(encoding="utf-8")
    assert "const canPost = tier >= 2 && accountExists && !banned && !locked;" in src
    assert "const canPost = tier >= 2 && accountExists && !banned && !locked && reputation" not in src
    assert "higher-trust posting band" not in src


def test_posting_minimum_remains_tier2_without_reputation_floor() -> None:
    onboarding = ONBOARDING.read_text(encoding="utf-8")
    create_post = CREATE_POST_PAGE.read_text(encoding="utf-8")
    assert "export const POSTING_MIN_TIER = 2;" in onboarding
    assert "export const POSTING_MIN_REPUTATION = 0;" in onboarding
    assert "tier >= POSTING_MIN_TIER" in create_post
    assert "POSTING_MIN_REPUTATION" not in create_post
