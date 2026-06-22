from __future__ import annotations

from pathlib import Path


def test_public_genesis_frontend_launch_journey_surfaces_registry_p2p_relay_and_safety_copy():
    root = Path(__file__).resolve().parents[2]
    node_dashboard = (root.parent / "web" / "src" / "pages" / "NodeDashboard.tsx").read_text(encoding="utf-8")
    e2e = (root.parent / "web" / "tests" / "e2e" / "public_observer_dashboard.spec.ts").read_text(encoding="utf-8")
    combined = node_dashboard + "\n" + e2e
    assert "seed_p2p_urls" in combined
    assert "seed_registry_signature_status" in combined
    assert "registry_source_kind" in combined or "registry source" in combined.lower()
    assert "relay" in combined.lower()
    assert "direct P2P" in combined or "direct" in combined.lower()
    assert "resettable" in combined.lower() or "public_beta_ready" in combined
    assert "live_economics" in combined or "economics" in combined.lower()
