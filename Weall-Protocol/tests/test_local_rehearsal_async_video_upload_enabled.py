from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _script() -> str:
    return (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(
        encoding="utf-8"
    )


def test_local_rehearsal_enables_async_video_upload_route_for_controlled_devnet() -> None:
    src = _script()

    assert "WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1" in src
    assert "endpoint is disabled\n    # unless explicitly enabled by the operator" in src

    genesis_start = src.index("Booting genesis backend")
    genesis_boot = src[genesis_start : src.index("_wait_http", genesis_start)]

    observer_start = src.index("Booting observer backend")
    observer_boot = src[observer_start : src.index("_wait_http", observer_start)]

    assert "WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1" in genesis_boot
    assert "WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1" in observer_boot


def test_local_rehearsal_upload_enable_is_paired_with_route_level_cap() -> None:
    src = _script()

    observer_start = src.index("Booting observer backend")
    observer_boot = src[observer_start : src.index("_wait_http", observer_start)]

    assert observer_boot.index("WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1") < observer_boot.index(
        "WEALL_POH_ASYNC_VIDEO_MAX_BYTES"
    )
    assert "104857600" in observer_boot
    assert "browser recording" in observer_boot
