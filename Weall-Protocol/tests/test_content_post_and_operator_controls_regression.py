from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor
from weall.runtime.gate_expr import eval_gate
from weall.runtime.poh.state import set_account_poh_status

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT.parent / "web" / "src"


def _executor_with_account(tmp_path: Path, *, legacy_tier: int, canonical_tier: int, canonical_status: str) -> WeAllExecutor:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "content-post-regression.db"),
        node_id="content-post-regression-node",
        chain_id="weall-controlled-devnet",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    st = ex.read_state()
    st["accounts"] = {
        "@poster": {
            "nonce": 20,
            "poh_tier": int(legacy_tier),
            "banned": False,
            "locked": False,
            "reputation": 0,
            "reputation_milli": 10_000,
            "keys": {"by_id": {"k:poster": {"pubkey": "k:poster", "revoked": False}}},
            "session_keys": {},
        }
    }
    set_account_poh_status(
        st,
        account_id="@poster",
        poh_tier=int(canonical_tier),
        status=canonical_status,
        issuer_authority_id="test_canonical_poh",
        mirror_legacy_account_field=False,
    )
    ex._ledger_store.write_state_snapshot(st)  # type: ignore[attr-defined]
    return ex


def _client(ex: WeAllExecutor) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = ex
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _content_post_tx(*, nonce: int = 21) -> dict[str, Any]:
    return {
        "chain_id": "weall-controlled-devnet",
        "tx_type": "CONTENT_POST_CREATE",
        "signer": "@poster",
        "nonce": int(nonce),
        "payload": {
            "post_id": f"post:@poster:{nonce}",
            "body": "public post after live verification",
            "visibility": "public",
            "tags": [],
            "media": [],
            "group_id": None,
        },
        "parent": None,
        "sig": "",
    }


def test_http_content_post_uses_canonical_poh_status_without_500(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    ex = _executor_with_account(tmp_path, legacy_tier=1, canonical_tier=2, canonical_status="active")

    response = _client(ex).post("/v1/tx/submit", json=_content_post_tx())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["status"] == "accepted"
    assert ex._mempool.size() == 1  # type: ignore[attr-defined]


def test_revoked_canonical_poh_blocks_content_post_without_server_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    ex = _executor_with_account(tmp_path, legacy_tier=2, canonical_tier=2, canonical_status="revoked")

    response = _client(ex).post("/v1/tx/submit", json=_content_post_tx())

    assert response.status_code == 403, response.text
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] in {"insufficient_poh_tier", "gate_denied"}
    assert "Internal Server Error" not in response.text


def test_gate_expressions_use_canonical_poh_status_for_tier_atoms() -> None:
    active = {"accounts": {"@poster": {"poh_tier": 1}}, "poh": {"account_status": {}}}
    set_account_poh_status(
        active,
        account_id="@poster",
        poh_tier=2,
        status="active",
        issuer_authority_id="test",
        mirror_legacy_account_field=False,
    )
    assert eval_gate("Tier2+", signer="@poster", state=active)[0] is True

    revoked = {"accounts": {"@poster": {"poh_tier": 2}}, "poh": {"account_status": {}}}
    set_account_poh_status(
        revoked,
        account_id="@poster",
        poh_tier=2,
        status="revoked",
        issuer_authority_id="test",
        mirror_legacy_account_field=False,
    )
    assert eval_gate("Tier2+", signer="@poster", state=revoked)[0] is False


def test_frontend_operator_controls_are_directly_deep_linked_and_opened() -> None:
    account_page = (WEB_ROOT / "pages" / "Account.tsx").read_text(encoding="utf-8")
    node_dashboard = (WEB_ROOT / "pages" / "NodeDashboard.tsx").read_text(encoding="utf-8")

    assert "accountOperatorSetupHref" in node_dashboard
    assert "?operator=1" in node_dashboard
    assert "Manage validator/storage opt-ins" in node_dashboard
    assert "Open validator/storage opt-ins" in node_dashboard

    assert "operatorSetupRequested" in account_page
    assert "shouldOpenOperatorPanel" in account_page
    assert 'open={shouldOpenOperatorPanel}' in account_page
    assert "Network service opt-ins: validator, storage, and helper setup" in account_page


def test_create_post_preflight_uses_onboarding_snapshot_tier() -> None:
    create_page = (WEB_ROOT / "pages" / "CreatePostPage.tsx").read_text(encoding="utf-8")

    assert "const tierNow = Number(snapshot.tier ?? 0);" in create_page
    assert "const tierNow = Number(acctState?.state?.poh_tier" not in create_page
