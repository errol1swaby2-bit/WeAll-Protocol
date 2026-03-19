from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _read_text_if_file(path_str: str | None) -> str:
    raw = str(path_str or "").strip()
    if not raw:
        return ""
    try:
        return Path(raw).read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def release_manifest_path() -> str:
    return str(os.environ.get("WEALL_RELEASE_MANIFEST_PATH", "") or "").strip()


def release_pubkey() -> str:
    inline = str(os.environ.get("WEALL_RELEASE_PUBKEY", "") or "").strip()
    if inline:
        return inline
    return _read_text_if_file(os.environ.get("WEALL_RELEASE_PUBKEY_FILE"))


def release_signing_privkey() -> str:
    inline = str(os.environ.get("WEALL_RELEASE_SIGNING_PRIVKEY", "") or "").strip()
    if inline:
        return inline
    return _read_text_if_file(os.environ.get("WEALL_RELEASE_SIGNING_PRIVKEY_FILE"))


def signed_manifest_required(*, mode: str, network_enabled: bool, bft_enabled: bool) -> bool:
    return _env_bool("WEALL_REQUIRE_SIGNED_BOOTSTRAP_MANIFEST", False)


def load_json_object(path: Path | None, *, kind: str) -> Json:
    if path is None:
        return {}
    if not path.is_file():
        raise FileNotFoundError(f"{kind} not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{kind} must be a JSON object")
    return payload


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_path(path: str | Path) -> Path:
    p = Path(path).expanduser()
    if p.is_absolute():
        return p
    return (_repo_root() / p).resolve()


def _empty_state() -> tuple[Json, Json]:
    state: Json = {
        "meta": {
            "chain_id": "",
            "schema_version": "1",
            "production_consensus_profile_hash": "",
            "tx_index_hash": "",
        },
        "chain": {"height": 0, "block_id": "", "block_hash": "", "state_root": ""},
        "bft": {"finalized_height": 0, "finalized_block_id": ""},
        "consensus": {
            "epochs": {"current": 0},
            "validator_set": {"set_hash": "", "active_set": []},
        },
        "roles": {"validators": {"active_set": []}},
        "accounts": {},
    }
    meta: Json = {
        "chain_id": "",
        "schema_version": "1",
        "production_consensus_profile_hash": "",
        "tx_index_hash": "",
        "db_initialized": False,
    }
    return state, meta


def read_db_state(db_path: str | Path) -> tuple[Json, Json]:
    resolved = _resolve_path(db_path)
    if not resolved.is_file():
        return _empty_state()

    try:
        con = sqlite3.connect(str(resolved))
        try:
            meta_rows = con.execute("SELECT key, value FROM meta").fetchall()
            meta: Json = {}
            for key, value in meta_rows:
                meta[str(key)] = value

            row = con.execute("SELECT state_json FROM ledger_state WHERE id = 1").fetchone()
            if row is None or not row[0]:
                state, fallback_meta = _empty_state()
                fallback_meta.update(meta)
                return state, fallback_meta

            raw_state = json.loads(str(row[0]))
            if not isinstance(raw_state, dict):
                state, fallback_meta = _empty_state()
                fallback_meta.update(meta)
                return state, fallback_meta

            state = raw_state
            state_meta = state.get("meta")
            if not isinstance(state_meta, dict):
                state_meta = {}
            merged_meta: Json = {
                "chain_id": str(state_meta.get("chain_id") or meta.get("chain_id") or ""),
                "schema_version": str(
                    meta.get("schema_version") or state_meta.get("schema_version") or "1"
                ),
                "production_consensus_profile_hash": str(
                    state_meta.get("production_consensus_profile_hash")
                    or meta.get("production_consensus_profile_hash")
                    or ""
                ),
                "tx_index_hash": str(
                    state_meta.get("tx_index_hash") or meta.get("tx_index_hash") or ""
                ),
                "db_initialized": True,
            }
            return state, merged_meta
        finally:
            con.close()
    except Exception:
        return _empty_state()


def _normalized_validators_from_state(state: Json) -> list[str]:
    consensus = state.get("consensus")
    roles = state.get("roles")
    validators: list[str] = []

    if isinstance(consensus, dict):
        validator_set = consensus.get("validator_set")
        if isinstance(validator_set, dict):
            active = validator_set.get("active_set")
            if isinstance(active, list):
                validators.extend(str(x).strip() for x in active if str(x).strip())

    if not validators and isinstance(roles, dict):
        validators_role = roles.get("validators")
        if isinstance(validators_role, dict):
            active = validators_role.get("active_set")
            if isinstance(active, list):
                validators.extend(str(x).strip() for x in active if str(x).strip())

    return sorted(set(v for v in validators if v))


def validator_epoch_and_hash(state: Json) -> tuple[int, str, list[str]]:
    consensus = state.get("consensus")
    epoch = 0
    set_hash = ""
    if isinstance(consensus, dict):
        epochs = consensus.get("epochs")
        if isinstance(epochs, dict):
            try:
                epoch = int(epochs.get("current") or 0)
            except Exception:
                epoch = 0
        validator_set = consensus.get("validator_set")
        if isinstance(validator_set, dict):
            set_hash = str(validator_set.get("set_hash") or "").strip()

    normalized = _normalized_validators_from_state(state)
    if not set_hash:
        set_hash = _sha256_hex(canon_json(normalized).encode("utf-8"))
    return int(epoch), str(set_hash), normalized


def build_anchor_from_state(state: Json) -> Json:
    meta = state.get("meta") if isinstance(state.get("meta"), dict) else {}
    chain = state.get("chain") if isinstance(state.get("chain"), dict) else {}
    bft = state.get("bft") if isinstance(state.get("bft"), dict) else {}
    anchor_payload = {
        "chain_id": str(meta.get("chain_id") or ""),
        "height": int(chain.get("height") or 0),
        "tip_hash": str(chain.get("block_hash") or chain.get("block_id") or ""),
        "finalized_height": int(bft.get("finalized_height") or 0),
        "finalized_block_id": str(bft.get("finalized_block_id") or ""),
    }
    return {
        **anchor_payload,
        "snapshot_hash": _sha256_hex(canon_json(anchor_payload).encode("utf-8")),
    }


def verify_anchor(*, expected: Json | None, observed: Json | None) -> list[str]:
    if not expected:
        return []
    if not observed:
        return ["trusted_anchor missing from local state"]
    issues: list[str] = []
    for field in (
        "chain_id",
        "height",
        "tip_hash",
        "finalized_height",
        "finalized_block_id",
        "snapshot_hash",
    ):
        if expected.get(field) != observed.get(field):
            issues.append(
                f"trusted_anchor mismatch:{field}: expected={expected.get(field)!r} observed={observed.get(field)!r}"
            )
    return issues


def expected_startup_fingerprint(
    *,
    cfg_chain_id: str,
    cfg_node_id: str,
    tx_index_hash: str,
    schema_version: str,
    validator_epoch: int,
    validator_set_hash_value: str,
) -> Json:
    payload = {
        "chain_id": str(cfg_chain_id or ""),
        "node_id": str(cfg_node_id or ""),
        "tx_index_hash": str(tx_index_hash or ""),
        "schema_version": str(schema_version or "1"),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash_value or ""),
    }
    return {
        **payload,
        "fingerprint": _sha256_hex(canon_json(payload).encode("utf-8")),
    }


def _manifest_payload(manifest: Json) -> Json:
    return {
        k: v
        for k, v in manifest.items()
        if k not in {"manifest_hash", "signature", "signer_pubkey"}
    }


def _computed_manifest_hash(manifest: Json) -> str:
    return _sha256_hex(canon_json(_manifest_payload(manifest)).encode("utf-8"))


def verify_manifest_integrity(manifest: Json) -> list[str]:
    issues: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]

    expected_hash = _computed_manifest_hash(manifest)
    observed_hash = str(manifest.get("manifest_hash") or "").strip()
    if not observed_hash:
        issues.append("missing manifest_hash")
    elif observed_hash != expected_hash:
        issues.append("manifest_hash mismatch")

    for key in (
        "chain_id",
        "node_id",
        "mode",
        "schema_version",
        "tx_index_hash",
        "trusted_anchor",
        "startup_fingerprint",
        "chain_config_compatibility",
        "chain_config_compatibility_hash",
    ):
        if key not in manifest:
            issues.append(f"missing manifest field: {key}")

    return issues


def _decode_key_bytes(s: str) -> bytes:
    raw = str(s or "").strip()
    if not raw:
        raise ValueError("empty key")
    try:
        return bytes.fromhex(raw)
    except Exception:
        import base64

        padding = "=" * (-len(raw) % 4)
        s2 = (raw + padding).replace("-", "+").replace("_", "/")
        return base64.b64decode(s2)


def sign_manifest(manifest: Json, *, privkey: str, signer_pubkey: str) -> Json:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    payload = dict(_manifest_payload(manifest))
    payload["manifest_hash"] = _computed_manifest_hash(payload)
    sk = Ed25519PrivateKey.from_private_bytes(_decode_key_bytes(privkey))
    sig = sk.sign(payload["manifest_hash"].encode("utf-8")).hex()
    payload["signer_pubkey"] = str(signer_pubkey or "").strip()
    payload["signature"] = sig
    return payload


def _verify_manifest_signature(manifest: Json, *, expected_pubkey: str) -> list[str]:
    issues: list[str] = []
    if not expected_pubkey:
        return issues

    signer_pubkey = str(manifest.get("signer_pubkey") or "").strip()
    signature = str(manifest.get("signature") or "").strip()
    if not signer_pubkey or not signature:
        return ["missing manifest signature"]

    if signer_pubkey != str(expected_pubkey).strip():
        issues.append("manifest signer pubkey mismatch")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pk = Ed25519PublicKey.from_public_bytes(_decode_key_bytes(expected_pubkey))
        current_hash = _computed_manifest_hash(manifest)
        pk.verify(bytes.fromhex(signature), current_hash.encode("utf-8"))
    except InvalidSignature:
        issues.append("manifest signature verification failed")
    except Exception as exc:
        issues.append(f"manifest signature verification failed: {exc}")

    return issues


def build_manifest(cfg: Any, *, db_path: Path, tx_index_path: Path) -> Json:
    from weall.runtime.chain_config import (
        chain_config_compatibility_hash,
        chain_config_compatibility_payload,
    )

    state, meta = read_db_state(db_path)
    tx_index_hash = _sha256_file(tx_index_path) if Path(tx_index_path).is_file() else ""
    validator_epoch, validator_set_hash_value, normalized_validators = validator_epoch_and_hash(
        state
    )
    schema_version = str(
        meta.get("schema_version")
        or ((state.get("meta") or {}) if isinstance(state.get("meta"), dict) else {}).get(
            "schema_version"
        )
        or "1"
    )
    startup_fingerprint = expected_startup_fingerprint(
        cfg_chain_id=str(cfg.chain_id or ""),
        cfg_node_id=str(cfg.node_id or ""),
        tx_index_hash=tx_index_hash,
        schema_version=schema_version,
        validator_epoch=validator_epoch,
        validator_set_hash_value=validator_set_hash_value,
    )
    manifest: Json = {
        "chain_id": str(cfg.chain_id or ""),
        "node_id": str(cfg.node_id or ""),
        "mode": str(cfg.mode or "").strip().lower(),
        "schema_version": schema_version,
        "tx_index_hash": tx_index_hash,
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash_value or ""),
        "normalized_validators": list(normalized_validators),
        "trusted_anchor": build_anchor_from_state(state),
        "startup_fingerprint": startup_fingerprint,
        "chain_config_compatibility": chain_config_compatibility_payload(cfg),
        "chain_config_compatibility_hash": chain_config_compatibility_hash(cfg),
    }
    manifest["manifest_hash"] = _computed_manifest_hash(manifest)
    return manifest


def verify_local_manifest(*, cfg: Any, manifest_path: Path, expected_pubkey: str) -> Json:
    from weall.runtime.chain_config import (
        chain_config_compatibility_hash,
        chain_config_compatibility_payload,
    )

    manifest = load_json_object(manifest_path, kind="release manifest")
    issues: list[str] = []
    issues.extend(verify_manifest_integrity(manifest))
    issues.extend(_verify_manifest_signature(manifest, expected_pubkey=expected_pubkey))

    state, meta = read_db_state(cfg.db_path)
    tx_index_path = Path(cfg.tx_index_path).resolve()
    local_tx_index_hash = _sha256_file(tx_index_path) if tx_index_path.is_file() else ""
    validator_epoch, validator_set_hash_value, normalized_validators = validator_epoch_and_hash(
        state
    )
    local_schema_version = str(
        meta.get("schema_version")
        or ((state.get("meta") or {}) if isinstance(state.get("meta"), dict) else {}).get(
            "schema_version"
        )
        or "1"
    )
    local_anchor = build_anchor_from_state(state)
    local_startup_fingerprint = expected_startup_fingerprint(
        cfg_chain_id=str(cfg.chain_id or ""),
        cfg_node_id=str(cfg.node_id or ""),
        tx_index_hash=local_tx_index_hash,
        schema_version=local_schema_version,
        validator_epoch=validator_epoch,
        validator_set_hash_value=validator_set_hash_value,
    )
    local_chain_cfg = chain_config_compatibility_payload(cfg)
    local_chain_cfg_hash = chain_config_compatibility_hash(cfg)

    mismatches: list[str] = []
    field_status: Json = {}

    def _check(field: str, local_value: Any, manifest_value: Any) -> None:
        ok = local_value == manifest_value
        field_status[field] = {
            "ok": ok,
            "local": local_value,
            "manifest": manifest_value,
        }
        if not ok:
            mismatches.append(field)
            issues.append(f"{field} mismatch: local={local_value!r} manifest={manifest_value!r}")

    _check("chain_id", str(cfg.chain_id or ""), str(manifest.get("chain_id") or ""))
    _check("tx_index_hash", local_tx_index_hash, str(manifest.get("tx_index_hash") or ""))
    _check(
        "startup_fingerprint",
        local_startup_fingerprint,
        manifest.get("startup_fingerprint"),
    )
    _check(
        "chain_config_compatibility_payload",
        local_chain_cfg,
        manifest.get("chain_config_compatibility"),
    )
    _check(
        "chain_config_compatibility_hash",
        local_chain_cfg_hash,
        str(manifest.get("chain_config_compatibility_hash") or ""),
    )
    _check(
        "validator_epoch",
        int(validator_epoch),
        int(manifest.get("validator_epoch") or 0),
    )
    _check(
        "validator_set_hash",
        str(validator_set_hash_value or ""),
        str(manifest.get("validator_set_hash") or ""),
    )
    _check(
        "normalized_validators",
        list(normalized_validators),
        list(manifest.get("normalized_validators") or []),
    )

    anchor_issues = verify_anchor(
        expected=manifest.get("trusted_anchor")
        if isinstance(manifest.get("trusted_anchor"), dict)
        else None,
        observed=local_anchor,
    )
    issues.extend(anchor_issues)

    compatibility_contract = {
        "ok": not mismatches and not anchor_issues,
        "mismatches": list(mismatches),
        "field_status": field_status,
        "local": {
            "chain_id": str(cfg.chain_id or ""),
            "tx_index_hash": local_tx_index_hash,
            "startup_fingerprint": local_startup_fingerprint,
            "chain_config_compatibility": local_chain_cfg,
            "chain_config_compatibility_hash": local_chain_cfg_hash,
            "trusted_anchor": local_anchor,
        },
        "manifest": {
            "chain_id": str(manifest.get("chain_id") or ""),
            "tx_index_hash": str(manifest.get("tx_index_hash") or ""),
            "startup_fingerprint": manifest.get("startup_fingerprint"),
            "chain_config_compatibility": manifest.get("chain_config_compatibility"),
            "chain_config_compatibility_hash": str(
                manifest.get("chain_config_compatibility_hash") or ""
            ),
            "trusted_anchor": manifest.get("trusted_anchor"),
        },
        "trusted_anchor_mismatches": list(anchor_issues),
    }

    return {
        "ok": not issues,
        "path": str(manifest_path),
        "pubkey": str(expected_pubkey or ""),
        "issues": issues,
        "compatibility_contract": compatibility_contract,
    }
