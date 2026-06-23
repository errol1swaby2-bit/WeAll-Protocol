from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts import messages as message_routes

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT.parent / "web"


def _auth_headers(account: str = "@errol") -> dict[str, str]:
    return {
        "x-weall-account": account,
        "x-weall-session-key": "session-key",
    }


def test_message_thread_list_falls_back_to_thread_membership_when_inbox_index_lags_batch451(monkeypatch) -> None:
    state = {
        "accounts": {
            "@errol": {"session_keys": {"session-key": {"active": True}}},
        },
        "messaging": {
            "inbox_by_account": {"@errol": {"threads": [], "messages": [], "last_nonce": 0}},
            "threads_by_id": {
                "dm:@devnet-genesis:@errol": {
                    "thread_id": "dm:@devnet-genesis:@errol",
                    "members": ["@devnet-genesis", "@errol"],
                    "created_at_nonce": 1,
                    "last_message_at_nonce": 20,
                    "last_message_id": "dm:@errol:20",
                    "message_ids": ["dm:@errol:20"],
                }
            },
            "messages_by_id": {
                "dm:@errol:20": {
                    "message_id": "dm:@errol:20",
                    "thread_id": "dm:@devnet-genesis:@errol",
                    "sender": "@errol",
                    "to": "@devnet-genesis",
                    "body": "",
                    "encrypted": True,
                    "encryption": {"scheme": "WEALL_E2EE_V1"},
                    "created_at_nonce": 20,
                }
            },
        },
    }

    app = FastAPI()
    app.include_router(message_routes.router, prefix="/v1")
    client = TestClient(app)

    res = client.get("/v1/messages/threads", headers=_auth_headers())
    assert res.status_code == 410, res.text
    assert res.json()["detail"]["code"] == "PRIVATE_MESSAGING_UNSUPPORTED"


def test_batch451_frontend_has_quiet_messaging_key_bootstrapper_and_retrying_recipient_lookup() -> None:
    bootstrapper = (WEB_ROOT / "src/components/MessagingKeyBootstrapper.tsx").read_text(encoding="utf-8")
    app = (WEB_ROOT / "src/App.tsx").read_text(encoding="utf-8")
    messaging = (WEB_ROOT / "src/pages/Messaging.tsx").read_text(encoding="utf-8")
    tx_queue = (WEB_ROOT / "src/components/TxQueueProvider.tsx").read_text(encoding="utf-8")

    assert "export default function MessagingKeyBootstrapper" in bootstrapper
    assert "return null" in bootstrapper
    assert "ACCOUNT_SECURITY_POLICY_SET" not in bootstrapper
    assert "<MessagingKeyBootstrapper />" not in app

    assert "PRIVATE_MESSAGING_UNSUPPORTED" in messaging
    assert "loadRecipientAccountWithMessagingKey" not in messaging

    assert "TX_RECORDED_AUTO_DISMISS_MS" in tx_queue
    assert "isTransientToastStatus" in tx_queue
    assert "safeLoadHistory" in tx_queue and "TX_VISIBLE_STALE_MS" in tx_queue
