from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def j(*parts: str) -> str:
    return "".join(parts)


FRONTEND_FILES = (
    OUTER / "web/src/api/weall.ts",
    OUTER / "web/src/pages/LoginPage.tsx",
    OUTER / "web/src/pages/PohPage.tsx",
    OUTER / "web/src/pages/Settings.tsx",
    OUTER / "web/DEPLOYMENT.md",
)

FORBIDDEN_PRIMARY_FLOW_MARKERS = (
    j("/v1/poh/", "email"),
    j("Poh", "Email"),
    j("poh", "Email"),
    j("email", "Oracle"),
    j("Email", "Oracle"),
    j("email_control_", "attestation"),
    j("verification ", "code"),
    j("official ", "sender"),
    j("VITE_", "WEALL_", "EMAIL"),
)


def test_frontend_primary_poh_flow_has_no_removed_email_adapter_markers() -> None:
    hits: list[str] = []

    for path in FRONTEND_FILES:
        assert path.exists(), f"expected frontend file to exist: {path}"

        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in FORBIDDEN_PRIMARY_FLOW_MARKERS:
            if marker in text:
                hits.append(f"{path.relative_to(OUTER)} contains removed primary-flow marker {marker!r}")

    assert not hits, "\n".join(hits)
