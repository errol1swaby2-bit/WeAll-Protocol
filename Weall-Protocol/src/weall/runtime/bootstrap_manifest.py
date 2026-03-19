from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from weall.crypto.sig import sign_ed25519, verify_ed25519_signature
from weall.runtime.bft_hotstuff import normalize_validators, validator_set_hash
from weall.runtime.chain_config import (
    ChainConfig,
    chain_config_compatibility_hash,
    chain_config_compatibility_payload,
    production_bootstrap_report,
)
from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE, runtime_startup_fingerprint

Json = dict[str, Any]


def canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_manifest_hash(manifest: Json) -> str:
    payload = dict(manifest)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)
    return hashlib.sha256(canon_json(payload).encode("utf-8")).hexdigest()


def verify_manifest_integrity(manifest: Json) -> list[str]:
    issues: list[str] = []
    expected = str(manifest.get("manifest_hash") or "").strip()
    if not expected:
        issues.append("manifest_hash missing")
        return issues
    observed = compute_manifest_hash(manifest)
    if observed != expected:
        issues.append(f"manifest_hash mismatch: computed={observed!r} manifest={expected!r}")
    return issues


def _read_secret_value(inline_env: str, file_env: str) -> str:
    inline = str(os.environ.get(inline_env, "") or "").strip()
    if inline:
        return inline
    fp = str(os.environ.get(file_env, "") or "").strip()
    if not fp:
        return ""
    try:
        return str(Path(fp).read_text(encoding="utf-8")).strip()
    except Exception:
        return ""


def signed_manifest_required(*, mode: str, network_enabled: bool, bft_enabled: bool) -> bool:
    raw = os.environ.get("WEALL_REQUIRE_SIGNED_BOOTSTRAP_MANIFEST")
    if raw is None:
        return False
    s = str(raw).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return False


def release_pubkey() -> str:
    return _read_secret_value("WEALL_RELEASE_PUBKEY", "WEALL_RELEASE_PUBKEY_FILE")


def release_signing_privkey() -> str:
    return _read_secret_value("WEALL_RELEASE_SIGNING_PRIVKEY", "WEALL_RELEASE_SIGNING_PRIVKEY_FILE")


def release_manifest_path() -> str:
    return str(os.environ.get("WEALL_RELEASE_MANIFEST_PATH", "") or "").strip()


def load_json_object(path: Path | None, *, kind: str) -> Json | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{kind} JSON must be an object")
    return payload


def read_db_state(db_path: Path) -> tuple[Json, dict[str, str]]:
    if not db_path.is_file():
        raise FileNotFoundError(f"db file not found: {db_path}")
    con = sqlite3.connect(str(db_path))
    try:
        meta_rows = con.execute("SELECT key, value FROM meta").fetchall()
        meta: dict[str, str] = {}
        for key, value in meta_rows:
            meta[str(key)] = str(value)
        row = con.execute("SELECT state_json FROM ledger_state WHERE id = 1").fetchone()
        if row is None or row[0] is None:
            raise RuntimeError("ledger_state row id=1 missing")
        state = json.loads(str(row[0]))
        if not isinstance(state, dict):
            raise RuntimeError("ledger_state payload is not a JSON object")
        return state, meta
    finally:
        con.close()


def build_anchor_from_state(state: Json) -> Json:
    chain = state.get("chain") if isinstance(state.get("chain"), dict) else {}
    bft = state.get("bft") if isinstance(state.get("bft"), dict) else {}
    return {
        "height": int(chain.get("height") or 0),
        "tip_block_id": str(chain.get("block_id") or ""),
        "tip_hash": str(chain.get("block_hash") or ""),
        "state_root": str(chain.get("state_root") or ""),
        "finalized_height": int(bft.get("finalized_height") or 0),
        "finalized_block_id": str(bft.get("finalized_block_id") or ""),
    }


def validator_epoch_and_hash(state: Json) -> tuple[int, str, list[str]]:
    consensus = state.get("consensus") if isinstance(state.get("consensus"), dict) else {}
    roles = state.get("roles") if isinstance(state.get("roles"), dict) else {}
    validator_set = consensus.get("validator_set") if isinstance(consensus, dict) else {}
    epochs = consensus.get("epochs") if isinstance(consensus, dict) else {}
    role_validators = roles.get("validators") if isinstance(roles, dict) else {}

    epoch = 0
    if isinstance(epochs, dict):
        try:
            epoch = int(epochs.get("current") or 0)
        except Exception:
            epoch = 0
    if epoch <= 0 and isinstance(validator_set, dict):
        try:
            epoch = int(validator_set.get("epoch") or 0)
        except Exception:
            epoch = 0

    active_raw: list[str] = []
    if isinstance(role_validators, dict) and isinstance(role_validators.get("active_set"), list):
        active_raw = list(role_validators.get("active_set") or [])
    elif isinstance(validator_set, dict) and isinstance(validator_set.get("active_set"), list):
        active_raw = list(validator_set.get("active_set") or [])

    normalized = normalize_validators([str(x).strip() for x in active_raw if str(x).strip()])
    persisted_set_hash = ""
    if isinstance(validator_set, dict):
        persisted_set_hash = str(validator_set.get("set_hash") or "").strip()
    computed_set_hash = validator_set_hash(normalized) if normalized else ""
    return epoch, (persisted_set_hash or computed_set_hash), normalized


def expected_startup_fingerprint(
    *,
    cfg_chain_id: str,
    cfg_node_id: str,
    tx_index_hash: str,
    schema_version: str,
    validator_epoch: int,
    validator_set_hash_value: str,
) -> Json:
    return runtime_startup_fingerprint(
        chain_id=cfg_chain_id,
        node_id=cfg_node_id,
        tx_index_hash=tx_index_hash,
        schema_version=schema_version,
        bft_enabled=True,
        validator_epoch=validator_epoch,
        validator_set_hash=validator_set_hash_value,
    )


def build_manifest(cfg: ChainConfig, *, db_path: Path, tx_index_path: Path) -> Json:
    state: Json = {}
    state_meta: dict[str, str] = {}
    if db_path.is_file():
        state, state_meta = read_db_state(db_path)
    tx_index_hash = sha256_file(tx_index_path) if tx_index_path.is_file() else ""
    anchor = build_anchor_from_state(state) if state else {}
    validator_epoch = 0
    validator_set_hash_value = ""
    if state:
        validator_epoch, validator_set_hash_value, _ = validator_epoch_and_hash(state)
    fp = expected_startup_fingerprint(
        cfg_chain_id=str(cfg.chain_id or ""),
        cfg_node_id=str(cfg.node_id or ""),
        tx_index_hash=tx_index_hash,
        schema_version=str(
            state_meta.get("schema_version")
            or ((state.get("meta") or {}) if isinstance(state.get("meta"), dict) else {}).get(
                "schema_version"
            )
            or "1"
        ),
        validator_epoch=validator_epoch,
        validator_set_hash_value=validator_set_hash_value,
    )
    manifest: Json = {
        "manifest_version": 1,
        "chain_id": str(cfg.chain_id or ""),
        "node_id": str(cfg.node_id or ""),
        "db_path": str(db_path),
        "tx_index_path": str(tx_index_path),
        "tx_index_hash": tx_index_hash,
        "protocol_profile": PRODUCTION_CONSENSUS_PROFILE.to_json(),
        "chain_config_compatibility": chain_config_compatibility_payload(cfg),
        "chain_config_compatibility_hash": chain_config_compatibility_hash(cfg),
        "protocol_profile_hash": PRODUCTION_CONSENSUS_PROFILE.profile_hash(),
        "startup_fingerprint": fp,
        "trusted_anchor": anchor,
        "bootstrap_report": production_bootstrap_report(cfg),
    }
    manifest["manifest_hash"] = compute_manifest_hash(manifest)
    return manifest


def sign_manifest(manifest: Json, *, privkey: str, signer_pubkey: str | None = None) -> Json:
    payload = dict(manifest)
    payload.pop("signature", None)
    message = canon_json(payload).encode("utf-8")
    sig = sign_ed25519(message=message, privkey=privkey, encoding="hex")
    signed = dict(payload)
    signed["signature"] = {
        "alg": "ed25519",
        "pubkey": str(signer_pubkey or "").strip(),
        "sig": sig,
    }
    return signed


def verify_manifest_signature(manifest: Json, *, expected_pubkey: str) -> list[str]:
    issues: list[str] = []
    sig_block = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
    alg = str(sig_block.get("alg") or "").strip().lower()
    pubkey = str(sig_block.get("pubkey") or "").strip()
    sig = str(sig_block.get("sig") or "").strip()
    if not sig_block and not expected_pubkey:
        return issues
    if alg != "ed25519":
        issues.append("manifest signature alg must be ed25519")
    if not sig:
        issues.append("manifest signature missing")
    if not expected_pubkey:
        issues.append("release public key missing")
    if pubkey and expected_pubkey and pubkey != expected_pubkey:
        issues.append("manifest signer pubkey mismatch")
    if issues:
        return issues
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    message = canon_json(unsigned).encode("utf-8")
    if not verify_ed25519_signature(message=message, sig=sig, pubkey=expected_pubkey):
        issues.append("manifest signature verification failed")
    return issues


def verify_anchor(*, expected: Json | None, observed: Json) -> list[str]:
    issues: list[str] = []
    if expected is None:
        return issues
    for key in (
        "height",
        "tip_block_id",
        "tip_hash",
        "state_root",
        "finalized_height",
        "finalized_block_id",
    ):
        want = expected.get(key)
        if want in (None, ""):
            continue
        have = observed.get(key)
        if str(have) != str(want):
            issues.append(f"trusted_anchor mismatch for {key}: db={have!r} expected={want!r}")
    return issues


def summarize_manifest_compatibility(
    *,
    cfg: ChainConfig,
    manifest: Json,
    tx_index_hash: str,
    schema_version: str,
    expected_anchor: Json,
    expected_fp: Json,
) -> Json:
    local_cfg_payload = chain_config_compatibility_payload(cfg)
    local_cfg_hash = chain_config_compatibility_hash(cfg)
    manifest_cfg_payload = (
        manifest.get("chain_config_compatibility")
        if isinstance(manifest.get("chain_config_compatibility"), dict)
        else {}
    )
    manifest_cfg_hash = str(manifest.get("chain_config_compatibility_hash") or "").strip()
    manifest_profile_hash = str(manifest.get("protocol_profile_hash") or "").strip()
    local_profile_hash = PRODUCTION_CONSENSUS_PROFILE.profile_hash()
    manifest_chain_id = str(manifest.get("chain_id") or "").strip()
    local_chain_id = str(cfg.chain_id or "").strip()
    manifest_tx_index_hash = str(manifest.get("tx_index_hash") or "").strip()
    manifest_fp = (
        manifest.get("startup_fingerprint")
        if isinstance(manifest.get("startup_fingerprint"), dict)
        else {}
    )
    manifest_anchor = (
        manifest.get("trusted_anchor") if isinstance(manifest.get("trusted_anchor"), dict) else {}
    )

    mismatches: list[str] = []
    field_status: Json = {
        "chain_id": manifest_chain_id == local_chain_id if manifest_chain_id else True,
        "protocol_profile_hash": manifest_profile_hash == local_profile_hash
        if manifest_profile_hash
        else True,
        "tx_index_hash": manifest_tx_index_hash == tx_index_hash
        if manifest_tx_index_hash and tx_index_hash
        else True,
        "chain_config_compatibility_hash": manifest_cfg_hash == local_cfg_hash
        if manifest_cfg_hash
        else True,
        "chain_config_compatibility_payload": canon_json(manifest_cfg_payload)
        == canon_json(local_cfg_payload)
        if manifest_cfg_payload
        else True,
        "startup_fingerprint": str(manifest_fp.get("fingerprint") or "")
        == str(expected_fp.get("fingerprint") or "")
        if manifest_fp
        else True,
    }
    if not field_status["chain_id"]:
        mismatches.append("chain_id")
    if not field_status["protocol_profile_hash"]:
        mismatches.append("protocol_profile_hash")
    if not field_status["tx_index_hash"]:
        mismatches.append("tx_index_hash")
    if not field_status["chain_config_compatibility_hash"]:
        mismatches.append("chain_config_compatibility_hash")
    if not field_status["chain_config_compatibility_payload"]:
        mismatches.append("chain_config_compatibility_payload")
    if not field_status["startup_fingerprint"]:
        mismatches.append("startup_fingerprint")

    anchor_mismatches: list[str] = []
    for key in (
        "height",
        "tip_block_id",
        "tip_hash",
        "state_root",
        "finalized_height",
        "finalized_block_id",
    ):
        want = manifest_anchor.get(key)
        if want in (None, ""):
            continue
        have = expected_anchor.get(key)
        if str(have) != str(want):
            anchor_mismatches.append(str(key))
    if anchor_mismatches:
        mismatches.append("trusted_anchor")

    return {
        "ok": not mismatches,
        "mismatches": mismatches,
        "field_status": field_status,
        "local": {
            "chain_id": local_chain_id,
            "protocol_profile_hash": local_profile_hash,
            "tx_index_hash": tx_index_hash,
            "schema_version": schema_version,
            "chain_config_compatibility": local_cfg_payload,
            "chain_config_compatibility_hash": local_cfg_hash,
            "startup_fingerprint": expected_fp,
            "trusted_anchor": expected_anchor,
        },
        "manifest": {
            "chain_id": manifest_chain_id,
            "protocol_profile_hash": manifest_profile_hash,
            "tx_index_hash": manifest_tx_index_hash,
            "chain_config_compatibility": manifest_cfg_payload,
            "chain_config_compatibility_hash": manifest_cfg_hash,
            "startup_fingerprint": manifest_fp,
            "trusted_anchor": manifest_anchor,
        },
        "trusted_anchor_mismatches": anchor_mismatches,
    }


def verify_local_manifest(*, cfg: ChainConfig, manifest_path: Path, expected_pubkey: str) -> Json:
    issues: list[str] = []
    try:
        manifest = load_json_object(manifest_path, kind="release manifest") or {}
    except Exception as exc:
        return {
            "ok": False,
            "required": True,
            "path": str(manifest_path),
            "issues": [f"failed to load release manifest: {exc}"],
        }

    issues.extend(verify_manifest_integrity(manifest))
    issues.extend(verify_manifest_signature(manifest, expected_pubkey=expected_pubkey))

    db_path = Path(str(cfg.db_path or "")).resolve()
    tx_index_path = Path(str(cfg.tx_index_path or "")).resolve()
    try:
        state, meta = read_db_state(db_path)
    except Exception as exc:
        return {
            "ok": False,
            "required": True,
            "path": str(manifest_path),
            "issues": [f"failed to load local db state: {exc}"],
        }

    if not tx_index_path.is_file():
        issues.append(f"tx_index_path missing: {str(tx_index_path)!r}")
        tx_index_hash = ""
    else:
        tx_index_hash = sha256_file(tx_index_path)

    schema_version = str(
        meta.get("schema_version")
        or ((state.get("meta") or {}) if isinstance(state.get("meta"), dict) else {}).get(
            "schema_version"
        )
        or "1"
    )
    validator_epoch, validator_set_hash_value, normalized_validators = validator_epoch_and_hash(
        state
    )
    observed_anchor = build_anchor_from_state(state)
    expected_fp = expected_startup_fingerprint(
        cfg_chain_id=str(cfg.chain_id or ""),
        cfg_node_id=str(cfg.node_id or ""),
        tx_index_hash=tx_index_hash,
        schema_version=schema_version,
        validator_epoch=validator_epoch,
        validator_set_hash_value=validator_set_hash_value,
    )

    expected_profile_hash = PRODUCTION_CONSENSUS_PROFILE.profile_hash()
    bundle_profile_hash = str(manifest.get("protocol_profile_hash") or "")
    if bundle_profile_hash and bundle_profile_hash != expected_profile_hash:
        issues.append(
            f"manifest protocol_profile_hash mismatch: binary={expected_profile_hash!r} manifest={bundle_profile_hash!r}"
        )
    bundle_tx_index_hash = str(manifest.get("tx_index_hash") or "")
    if bundle_tx_index_hash and tx_index_hash and bundle_tx_index_hash != tx_index_hash:
        issues.append(
            f"manifest tx_index_hash mismatch: local={tx_index_hash!r} manifest={bundle_tx_index_hash!r}"
        )
    bundle_chain_id = str(manifest.get("chain_id") or "")
    if bundle_chain_id and bundle_chain_id != str(cfg.chain_id or ""):
        issues.append(
            f"manifest chain_id mismatch: config={str(cfg.chain_id or '')!r} manifest={bundle_chain_id!r}"
        )
    local_cfg_hash = chain_config_compatibility_hash(cfg)
    bundle_cfg_hash = str(manifest.get("chain_config_compatibility_hash") or "").strip()
    bundle_cfg_payload = (
        manifest.get("chain_config_compatibility")
        if isinstance(manifest.get("chain_config_compatibility"), dict)
        else None
    )
    if bundle_cfg_payload is not None:
        expected_cfg_payload = chain_config_compatibility_payload(cfg)
        if canon_json(bundle_cfg_payload) != canon_json(expected_cfg_payload):
            issues.append(
                f"manifest chain_config_compatibility mismatch: local={canon_json(expected_cfg_payload)!r} manifest={canon_json(bundle_cfg_payload)!r}"
            )
    if bundle_cfg_hash and bundle_cfg_hash != local_cfg_hash:
        issues.append(
            f"manifest chain_config_compatibility_hash mismatch: local={local_cfg_hash!r} manifest={bundle_cfg_hash!r}"
        )
    issues.extend(
        verify_anchor(
            expected=manifest.get("trusted_anchor")
            if isinstance(manifest.get("trusted_anchor"), dict)
            else None,
            observed=observed_anchor,
        )
    )
    bundle_fp = (
        manifest.get("startup_fingerprint")
        if isinstance(manifest.get("startup_fingerprint"), dict)
        else {}
    )
    bundle_hash = str(bundle_fp.get("fingerprint") or "")
    if bundle_hash and bundle_hash != str(expected_fp.get("fingerprint") or ""):
        issues.append(
            f"manifest startup_fingerprint mismatch: local={expected_fp.get('fingerprint')!r} manifest={bundle_hash!r}"
        )

    compatibility_contract = summarize_manifest_compatibility(
        cfg=cfg,
        manifest=manifest,
        tx_index_hash=tx_index_hash,
        schema_version=schema_version,
        expected_anchor=observed_anchor,
        expected_fp=expected_fp,
    )

    return {
        "ok": not issues,
        "required": True,
        "path": str(manifest_path),
        "pubkey": str(expected_pubkey or ""),
        "protocol_profile_hash": expected_profile_hash,
        "chain_config_compatibility": chain_config_compatibility_payload(cfg),
        "chain_config_compatibility_hash": chain_config_compatibility_hash(cfg),
        "tx_index_hash": tx_index_hash,
        "schema_version": schema_version,
        "validator_epoch": validator_epoch,
        "validator_set_hash": validator_set_hash_value,
        "normalized_validators": normalized_validators,
        "startup_fingerprint": expected_fp,
        "trusted_anchor": observed_anchor,
        "compatibility_contract": compatibility_contract,
        "issues": issues,
    }
