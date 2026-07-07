#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from typing import Any

Json = dict[str, Any]

_SIGNER_ID = "weall-release-signer-testnet-staging-v1"
_SECRET = b"weall-testnet-staging-signature-domain-v1"


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(obj: Any) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


def _sign(payload_hash: str, signer: str = _SIGNER_ID) -> str:
    return hashlib.sha256(_SECRET + signer.encode("utf-8") + payload_hash.encode("utf-8")).hexdigest()


def _verify(manifest: Json, allowed_signers: set[str]) -> tuple[bool, str]:
    signer = str(manifest.get("signer_id", ""))
    if signer not in allowed_signers:
        return False, "signer_not_allowed"
    body = {k: v for k, v in manifest.items() if k not in {"signature", "artifact_hash", "signer_id"}}
    artifact_hash = _digest(body)
    if str(manifest.get("artifact_hash")) != artifact_hash:
        return False, "artifact_hash_mismatch"
    if str(manifest.get("signature")) != _sign(artifact_hash, signer):
        return False, "signature_invalid"
    if bool(manifest.get("auto_apply")) or bool(manifest.get("execute_migration")):
        return False, "auto_apply_forbidden"
    return True, "verified_for_staging_only"


def run_harness() -> Json:
    body = {
        "schema": "weall.protocol_upgrade.signed_staging_manifest.v1",
        "upgrade_id": "upgrade:testnet-readiness-mechanism-pack:589",
        "version": "v1.5-testnet-mechanism-b589",
        "chain_id": "weall-testnet-candidate",
        "artifact_cid": "bafytestnetstagedartifact0000000000000000000000000000000",
        "artifact_sha256": hashlib.sha256(b"deterministic staged artifact bytes").hexdigest(),
        "migration_vector_hash": hashlib.sha256(b"no migration executed in b589").hexdigest(),
        "rollback_vector_hash": hashlib.sha256(b"rollback plan documented but not executed").hexdigest(),
        "compatibility_window_heights": [1200, 1800],
        "operator_action_required": True,
        "auto_apply": False,
        "execute_migration": False,
        "rollback_execute": False,
    }
    artifact_hash = _digest(body)
    manifest = {**body, "signer_id": _SIGNER_ID, "artifact_hash": artifact_hash, "signature": _sign(artifact_hash)}
    good_ok, good_reason = _verify(manifest, {_SIGNER_ID})
    tampered = {**manifest, "artifact_sha256": "00" * 32}
    tampered_ok, tampered_reason = _verify(tampered, {_SIGNER_ID})
    wrong_signer = {**manifest, "signer_id": "unknown-signer"}
    wrong_ok, wrong_reason = _verify(wrong_signer, {_SIGNER_ID})
    auto_body = {**body, "auto_apply": True}
    auto_hash = _digest(auto_body)
    auto_apply = {**auto_body, "signer_id": _SIGNER_ID, "artifact_hash": auto_hash, "signature": _sign(auto_hash)}
    auto_ok, auto_reason = _verify(auto_apply, {_SIGNER_ID})
    no_side_effects = {
        "artifact_fetched": False,
        "software_applied": False,
        "migration_executed": False,
        "rollback_executed": False,
        "node_restarted": False,
    }
    return {
        "ok": bool(good_ok and not tampered_ok and not wrong_ok and not auto_ok and all(v is False for v in no_side_effects.values())),
        "batch": "589",
        "mechanism": "signed_artifact_staging_manifest_verification_without_execution",
        "valid_manifest_verified": good_ok,
        "valid_manifest_reason": good_reason,
        "tampered_manifest_rejected": tampered_reason == "artifact_hash_mismatch",
        "wrong_signer_rejected": wrong_reason == "signer_not_allowed",
        "auto_apply_rejected": auto_reason == "auto_apply_forbidden",
        "manifest": manifest,
        "side_effects": no_side_effects,
        "operator_action_required": True,
        "automatic_protocol_upgrade_enabled": False,
    }


if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
