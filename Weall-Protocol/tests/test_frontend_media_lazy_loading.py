from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "src"


def test_feed_view_resolves_visible_media_without_full_state_snapshot() -> None:
    feed = (WEB / "components" / "FeedView.tsx").read_text(encoding="utf-8")
    assert "loadMediaIndexFromSnapshot" not in feed
    assert "/v1/state/snapshot" not in feed
    assert "weall.mediaResolve(ids" in feed
    assert "collectMediaIds(pageItems)" in feed


def test_media_gallery_uses_viewport_observer_and_local_proxy() -> None:
    gallery = (WEB / "components" / "MediaGallery.tsx").read_text(encoding="utf-8")
    api = (WEB / "api" / "weall.ts").read_text(encoding="utf-8")

    assert "IntersectionObserver" in gallery
    assert "rootMargin = \"640px\"" in gallery
    assert "weall.mediaProxyUrl" in gallery
    assert "loading=\"lazy\"" in gallery
    assert "decoding=\"async\"" in gallery
    assert "preload=\"none\"" in gallery
    assert "/v1/media/proxy/" in api
    assert "mediaResolve(ids" in api
