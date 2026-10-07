from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _ForensicsExecutor:
    chain_id = "p2-forensics-chain"
    node_id = "@validator"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "height": 9,
            "tip": "block:9",
            "finalized": {"height": 7},
            "roles": {"validators": {"active_set": ["@a", "@b", "@c", "@d"]}},
            "consensus": {"validator_set": {"set_hash": "validator-set-hash"}},
        }

    def bft_operator_forensics(self) -> dict[str, object]:
        return {
            "ok": True,
            "chain_id": self.chain_id,
            "node_id": self.node_id,
            "recent_rejection_summary": {"count": 1, "latest": {"reason": "missing_parent"}},
            "pending_fetch_request_descriptors": [{"block_id": "parent-secret-timing"}],
            "pending_outbound_messages": [{"kind": "vote"}],
            "journal_tail": [{"event": "internal-bft-recovery"}],
        }


def _client() -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _ForensicsExecutor()
    return TestClient(app)


def test_prod_anonymous_forensics_is_strict_public_projection(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CONSENSUS_FORENSICS_OPERATOR_TOKEN", "operator-secret")

    response = _client().get("/v1/status/consensus/forensics")

    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "public_consensus_health"
    assert body["chain_id"] == "p2-forensics-chain"
    assert body["height"] == 9
    for forbidden in (
        "node_id",
        "diagnostics",
        "recent_rejection_summary",
        "pending_fetch_request_descriptors",
        "pending_outbound_messages",
        "journal_tail",
    ):
        assert forbidden not in body


def test_prod_wrong_forensics_token_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CONSENSUS_FORENSICS_OPERATOR_TOKEN", "operator-secret")

    response = _client().get(
        "/v1/status/consensus/forensics",
        headers={"X-WeAll-Consensus-Forensics-Token": "wrong"},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "forbidden"


def test_prod_operator_token_receives_bounded_full_forensics(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CONSENSUS_FORENSICS_OPERATOR_TOKEN", "operator-secret")

    response = _client().get(
        "/v1/status/consensus/forensics",
        headers={"X-WeAll-Consensus-Forensics-Token": "operator-secret"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["node_id"] == "@validator"
    assert body["recent_rejection_summary"]["latest"]["reason"] == "missing_parent"
    assert body["pending_fetch_request_descriptors"][0]["block_id"] == "parent-secret-timing"
