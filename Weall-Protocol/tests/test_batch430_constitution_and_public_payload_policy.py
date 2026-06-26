from __future__ import annotations

import hashlib
from pathlib import Path

from weall.runtime.chain_manifest import chain_manifest_status, load_chain_manifest
from weall.runtime.constitution import active_constitution_commitment, constitution_document_hash
from weall.runtime.public_protocol_policy import (
    OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED,
    public_protocol_policy_violation,
)
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def test_constitution_hash_is_bound_into_canonical_chain_manifest_batch430() -> None:
    manifest = load_chain_manifest(str(ROOT / "configs" / "chains" / "weall-genesis.json"), required=True)
    assert manifest is not None
    expected_hash = hashlib.sha256((ROOT / "docs" / "constitution" / "WEALL_GENESIS_CONSTITUTION_DRAFT_2.md").read_bytes()).hexdigest()
    assert manifest.constitution_version == "draft-2"
    assert manifest.constitution_hash == expected_hash == constitution_document_hash()
    commitment = active_constitution_commitment(manifest.raw)
    assert commitment["active"] is True
    assert commitment["status"] == "genesis_bound"


def test_chain_manifest_status_reports_constitution_commitments_batch430() -> None:
    manifest = load_chain_manifest(str(ROOT / "configs" / "chains" / "weall-genesis.json"), required=True)
    report = chain_manifest_status(manifest=manifest, chain_id="weall-prod", mode="prod", strict=True)
    assert report["constitution_version"] == "draft-2"
    assert report["constitution_hash"]
    assert "chain_manifest_constitution_hash_unpinned" not in report["issues"]


def test_public_policy_rejects_non_inspectable_protocol_payload_batch430() -> None:
    env = TxEnvelope(
        tx_type="CONTENT_POST_CREATE",
        signer="alice",
        nonce=1,
        payload={"post_id": "post:1", "body": "public summary", "encrypted" + "_payload": "opaque"},
        sig="sig",
    )
    violation = public_protocol_policy_violation(env)
    assert violation is not None
    assert violation.code == OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED
    assert violation.details["field"] == "encrypted" + "_payload"
