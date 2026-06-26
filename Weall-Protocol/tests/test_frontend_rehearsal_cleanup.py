from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "src"
SCRIPTS = ROOT / "Weall-Protocol" / "scripts"
SRC = ROOT / "Weall-Protocol" / "src"


def test_media_gallery_is_proxy_first_and_does_not_autoload_direct_http() -> None:
    gallery = (WEB / "components" / "MediaGallery.tsx").read_text(encoding="utf-8")

    assert "function deriveExternalUrl" in gallery
    assert "Direct HTTP gateway/provider URLs are intentionally not auto-loaded" in gallery
    assert "Open external attachment" in gallery
    assert "External media is not auto-loaded" in gallery
    assert "return direct;" not in gallery
    assert "return weall.mediaProxyUrl(cid, base);" in gallery


def test_dispute_and_juror_pages_prefer_scoped_content_reads() -> None:
    juror = (WEB / "pages" / "JurorDashboard.tsx").read_text(encoding="utf-8")
    detail = (WEB / "pages" / "DisputeDetail.tsx").read_text(encoding="utf-8")

    assert "weall.contentScoped(targetId, apiBase, headers)" in juror
    assert "getAuthHeaders" in detail
    assert "weall.contentScoped(targetId, apiBase, headers)" in detail


def test_api_smoke_uses_public_tx_submit_not_legacy_mempool_submit() -> None:
    smoke = (SCRIPTS / "api_smoke.sh").read_text(encoding="utf-8")

    assert 'python3 - "$1"' in smoke
    assert "/v1/chain/identity" in smoke
    assert '"chain_id": "${CHAIN_ID}"' in smoke
    assert "/v1/tx/submit" in smoke
    assert "/v1/mempool/submit" not in smoke


def test_validator_attester_polls_status_before_broad_snapshot() -> None:
    attester = (SRC / "weall" / "services" / "validator_attester.py").read_text(encoding="utf-8")

    assert "def _read_head_status" in attester
    assert 'f"{producer_url}/v1/status"' in attester
    assert "attester_status_failed" in attester
    assert "_read_head_status(producer_url)" in attester
