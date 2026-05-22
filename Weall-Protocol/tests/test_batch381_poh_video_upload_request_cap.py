from __future__ import annotations

from starlette.applications import Starlette

from weall.api.security import RequestSizeLimitMiddleware


def _middleware() -> RequestSizeLimitMiddleware:
    return RequestSizeLimitMiddleware(Starlette())


def test_async_poh_video_upload_uses_dedicated_file_cap(monkeypatch):
    monkeypatch.setenv("WEALL_MAX_REQUEST_BYTES", "128")
    monkeypatch.delenv("WEALL_MAX_JSON_BYTES", raising=False)
    monkeypatch.setenv("WEALL_POH_ASYNC_VIDEO_MAX_BYTES", str(4 * 1024 * 1024))
    monkeypatch.setenv("WEALL_MEDIA_MULTIPART_OVERHEAD_BYTES", str(512 * 1024))

    middleware = _middleware()

    assert middleware._effective_max_bytes("/v1/tx/submit") == 128
    assert middleware._effective_max_bytes("/v1/poh/async/evidence/video/upload") == (
        4 * 1024 * 1024 + 512 * 1024
    )


def test_tier2_poh_video_upload_uses_dedicated_file_cap(monkeypatch):
    monkeypatch.setenv("WEALL_MAX_REQUEST_BYTES", "128")
    monkeypatch.delenv("WEALL_MAX_JSON_BYTES", raising=False)
    monkeypatch.setenv("WEALL_POH_TIER2_VIDEO_MAX_BYTES", str(5 * 1024 * 1024))
    monkeypatch.setenv("WEALL_MEDIA_MULTIPART_OVERHEAD_BYTES", str(256 * 1024))

    middleware = _middleware()

    assert middleware._effective_max_bytes("/v1/poh/tier2/video/upload") == (
        5 * 1024 * 1024 + 256 * 1024
    )


def test_existing_media_upload_cap_is_unchanged(monkeypatch):
    monkeypatch.setenv("WEALL_MAX_REQUEST_BYTES", "128")
    monkeypatch.delenv("WEALL_MAX_JSON_BYTES", raising=False)
    monkeypatch.setenv("WEALL_IPFS_MAX_UPLOAD_BYTES", str(3 * 1024 * 1024))
    monkeypatch.setenv("WEALL_MEDIA_MULTIPART_OVERHEAD_BYTES", str(64 * 1024))

    middleware = _middleware()

    assert middleware._effective_max_bytes("/v1/media/upload") == (
        3 * 1024 * 1024 + 64 * 1024
    )


def test_local_rehearsal_exports_async_video_cap():
    script = open("scripts/devnet_local_two_frontend_rehearsal.sh", encoding="utf-8").read()

    assert "WEALL_POH_ASYNC_VIDEO_MAX_BYTES" in script
    assert "104857600" in script
    assert "browser recording" in script
