from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = REPO_ROOT.parent
WEB_ROOT = OUTER_ROOT / "web"


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected frontend file: {path}"
    return path.read_text(encoding="utf-8")


def _j(*parts: str) -> str:
    return "".join(parts)


def test_frontend_api_client_has_no_known_type_syntax_regression() -> None:
    text = _read(WEB_ROOT / "src" / "api" / "weall.ts")

    assert "function withSearch(function withSearch(" not in text
    assert len(re.findall(r"\bissued_at_ts\?: number;", text)) == 1


def test_frontend_routes_do_not_require_removed_user_tier_or_noop_message_fab() -> None:
    text = _read(WEB_ROOT / "src" / "lib" / "router.ts")

    assert not re.search(r"minPohTier:\s*[3-9]", text)

    # Production route metadata must not expose a no-op messages FAB.
    assert 'fab: "message"' not in text
    assert "case \"message\"" not in text

    fab_type = re.search(r"type FabAction = .*?;", text, flags=re.S)
    assert fab_type is not None
    assert '"message"' not in fab_type.group(0)


def test_frontend_does_not_call_removed_identity_authority_routes() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (WEB_ROOT / "src").rglob("*")
        if path.is_file() and path.suffix in {".ts", ".tsx"}
    )

    forbidden_fragments = [
        _j("/v1/poh/", "em", "ail"),
        _j("/v1/", "or", "acle"),
        _j("POH_", "EM", "AIL"),
        _j("OR", "ACLE", "_"),
        _j("POH_", "TIER", "3"),
    ]

    for fragment in forbidden_fragments:
        assert fragment not in combined


def test_frontend_identity_copy_is_native_two_tier_language() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (WEB_ROOT / "src").rglob("*")
        if path.is_file() and path.suffix in {".ts", ".tsx"}
    )

    assert "Async Verified Human" in combined
    assert "Live Verified Human" in combined

    forbidden_identity_copy = [
        _j("em", "ail", " verification"),
        _j("Cloud", "flare"),
        _j("SM", "TP"),
        _j("D", "NS"),
        _j("or", "acle", " verification"),
    ]

    lowered = combined.lower()
    for phrase in forbidden_identity_copy:
        assert phrase.lower() not in lowered
