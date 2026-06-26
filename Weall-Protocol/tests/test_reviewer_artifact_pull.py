from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.reviewer_artifacts import router


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_reviewer_artifact_routes_expose_only_public_bundle_and_manifest(tmp_path: Path, monkeypatch) -> None:
    public_dir = tmp_path / "public"
    public_dir.mkdir()

    bundle = {
        "type": "weall_node_operator_onboarding_bundle",
        "version": 1,
        "observer": {"genesis_api_base": "http://127.0.0.1:8000"},
    }
    manifest = {
        "schema_version": "1",
        "chain_id": "weall-reviewer-lan",
        "trusted_authority_pubkeys": ["abc"],
    }
    index = {"ok": True, "type": "weall_reviewer_public_artifact_index"}

    (public_dir / "weall-external-observer-bundle.json").write_text(
        json.dumps(bundle, sort_keys=True), encoding="utf-8"
    )
    (public_dir / "reviewer-chain-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    (public_dir / "artifact-index.json").write_text(
        json.dumps(index, sort_keys=True), encoding="utf-8"
    )

    monkeypatch.setenv("WEALL_REVIEWER_ARTIFACTS_ENABLED", "1")
    monkeypatch.setenv("WEALL_REVIEWER_ARTIFACTS_DIR", str(public_dir))

    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)

    idx = client.get("/v1/reviewer/artifacts")
    assert idx.status_code == 200
    idx_json = idx.json()
    assert idx_json["ok"] is True
    assert idx_json["artifacts"]["bundle"]["url"] == "/v1/reviewer/artifacts/bundle"
    assert idx_json["artifacts"]["manifest"]["url"] == "/v1/reviewer/artifacts/manifest"

    bundle_resp = client.get("/v1/reviewer/artifacts/bundle")
    manifest_resp = client.get("/v1/reviewer/artifacts/manifest")
    assert bundle_resp.status_code == 200
    assert manifest_resp.status_code == 200
    assert bundle_resp.json()["type"] == "weall_node_operator_onboarding_bundle"
    assert manifest_resp.json()["chain_id"] == "weall-reviewer-lan"

    serialized = json.dumps(idx_json, sort_keys=True).lower()
    assert "private-key" not in serialized
    assert "reviewer-genesis.env" not in serialized
    assert "sqlite" not in serialized


def test_reviewer_artifact_routes_disabled_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WEALL_REVIEWER_ARTIFACTS_ENABLED", raising=False)
    monkeypatch.setenv("WEALL_REVIEWER_ARTIFACTS_DIR", str(tmp_path))

    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)

    assert client.get("/v1/reviewer/artifacts").status_code == 404
    assert client.get("/v1/reviewer/artifacts/bundle").status_code == 404
    assert client.get("/v1/reviewer/artifacts/manifest").status_code == 404


def test_app_mounts_reviewer_artifact_router() -> None:
    text = _read("src/weall/api/app.py")
    assert "reviewer_artifacts_router" in text
    assert 'app.include_router(reviewer_artifacts_router, prefix="/v1")' in text


def test_genesis_wrapper_publishes_artifact_routes_and_pull_command() -> None:
    text = _read("scripts/reviewer_lan_genesis_rehearsal.sh")
    assert "WEALL_REVIEWER_ARTIFACTS_ENABLED=1" in text
    assert "WEALL_REVIEWER_ARTIFACTS_DIR" in text
    assert "/v1/reviewer/artifacts" in text
    assert "/v1/reviewer/artifacts/bundle" in text
    assert "/v1/reviewer/artifacts/manifest" in text
    assert "--pull-reviewer-artifacts" in text
    assert "reviewer-genesis.env" not in text
    assert "private-key.hex" not in text


def test_observer_wrapper_can_pull_reviewer_artifacts() -> None:
    text = _read("scripts/reviewer_observer_rehearsal.sh")
    assert "--pull-reviewer-artifacts" in text
    assert "--artifact-dir" in text
    assert "/v1/reviewer/artifacts/bundle" in text
    assert "/v1/reviewer/artifacts/manifest" in text
    assert "python3 -m json.tool" in text
    assert "Use --pull-reviewer-artifacts or pass --bundle" in text
    assert "Use --pull-reviewer-artifacts or pass --manifest" in text


def test_quickstart_documents_artifact_pull_flow() -> None:
    text = _read("docs/REVIEWER_LAN_REHEARSAL_QUICKSTART.md")
    assert "--pull-reviewer-artifacts" in text
    assert "/v1/reviewer/artifacts" in text
    assert "observer script downloads these public files automatically" in text.lower()
    assert "reviewer private keys" in text
    assert "canonical production Genesis authority" in text
