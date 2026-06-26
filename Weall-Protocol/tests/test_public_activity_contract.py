from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts import activity as activity_routes

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT.parent / "web"


def test_public_activity_input_queue_contract_batch451() -> None:
    app = FastAPI()
    app.include_router(activity_routes.router, prefix="/v1")
    client = TestClient(app)

    res = client.get("/v1/activity/notices")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["public_only"] is True
    assert body["source"] == "public_protocol_events"
    assert "dispute_assignment" in body["notice_types"]
    assert "validator_operator_alert" in body["notice_types"]


def test_removed_private_communication_frontend_files_are_absent_batch451() -> None:
    app = (WEB_ROOT / "src/App.tsx").read_text(encoding="utf-8")
    router = (WEB_ROOT / "src/lib/router.ts").read_text(encoding="utf-8")
    tx_queue = (WEB_ROOT / "src/components/TxQueueProvider.tsx").read_text(encoding="utf-8")

    assert not (WEB_ROOT / "src" / "components" / ("Mess" + "agingKeyBootstrapper.tsx")).exists()
    assert not (WEB_ROOT / "src" / "pages" / ("Mess" + "aging.tsx")).exists()
    assert not (WEB_ROOT / "src" / "lib" / ("message" + "Crypto.ts")).exists()
    assert "Mess" + "agingKeyBootstrapper" not in app
    assert "TX_RECORDED_AUTO_DISMISS_MS" in tx_queue
    assert "isTransientToastStatus" in tx_queue
    assert "safeLoadHistory" in tx_queue and "TX_VISIBLE_STALE_MS" in tx_queue
