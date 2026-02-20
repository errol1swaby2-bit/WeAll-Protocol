from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

from weall.runtime.gates import resolve_signer_authz
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_admission_types import TxEnvelope, TxVerdict
from weall.runtime.tx_schema import validate_payload
from weall.tx.canon import TxIndex

Json = Dict[str, Any]


def _get_txdef(idx: Any, tx_type: str) -> Optional[Dict[str, Any]]:
    t = tx_type.strip().upper()

    by_name = getattr(idx, "by_name", None)
    if isinstance(by_name, dict):
        d = by_name.get(t)
        if isinstance(d, dict):
            return d

    tx_types = getattr(idx, "tx_types", None)
    if isinstance(tx_types, list):
        for d in tx_types:
            if str(d.get("name", "")).strip().upper() == t:
                return d
    return None


def _require(payload: Dict[str, Any], key: str) -> Optional[TxVerdict]:
    v = payload.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        return TxVerdict.reject("invalid_payload", f"missing_{key}", {"missing": key})
    return None


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return bool(default)
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _is_unsafe_dev_mode() -> bool:
    """Return True only for explicitly unsafe local-dev runs.

    We require BOTH:
      - WEALL_MODE=testnet
      - WEALL_UNSAFE_DEV=1

    This prevents accidentally running with relaxed security flags in production.
    """
    mode = (os.getenv("WEALL_MODE") or "").strip().lower()
    if mode != "testnet":
        return False
    return _env_bool("WEALL_UNSAFE_DEV", False)


def _normalize_jsonable(obj: Any) -> Any:
    """Return a JSON-serializable representation of obj where possible."""
    if obj is None:
        return None
    if isinstance(obj, (dict, list, str, int, float, bool)):
        return obj
    # TxEnvelope / similar
    to_json = getattr(obj, "to_json", None)
    if callable(to_json):
        try:
            return to_json()
        except Exception:
            return obj
    # Pydantic-ish
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        try:
            return model_dump()
        except Exception:
            return obj
    return obj


def _json_size_bytes(obj: Any) -> int:
    """Compute JSON byte size. If not serializable, return -1 (unknown)."""
    try:
        norm = _normalize_jsonable(obj)
        # sort_keys=True to avoid cross-node / cross-path key-order differences affecting sizing.
        return len(json.dumps(norm, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8"))
    except Exception:
        return -1


def _validate_payload_limits(payload: Any) -> Optional[TxVerdict]:
    """Generic payload validation (shape + size caps)."""
    if payload is None:
        return TxVerdict.reject("invalid_payload", "payload_required", {"expected": "object"})
    if not isinstance(payload, dict):
        return TxVerdict.reject("invalid_payload", "payload_must_be_object", {"type": str(type(payload))})

    max_payload_bytes = _env_int("WEALL_MAX_TX_PAYLOAD_BYTES", 64 * 1024)  # 64 KiB
    max_payload_keys = _env_int("WEALL_MAX_TX_PAYLOAD_KEYS", 256)
    max_string_bytes = _env_int("WEALL_MAX_TX_STRING_BYTES", 8 * 1024)  # 8 KiB per string
    max_list_len = _env_int("WEALL_MAX_TX_LIST_LEN", 10_000)
    max_depth = _env_int("WEALL_MAX_TX_NESTING", 10)

    if len(payload) > int(max_payload_keys):
        return TxVerdict.reject(
            "invalid_payload",
            "payload_too_many_keys",
            {"keys": len(payload), "max_keys": int(max_payload_keys)},
        )

    payload_bytes = _json_size_bytes(payload)
    if payload_bytes >= 0 and payload_bytes > int(max_payload_bytes):
        return TxVerdict.reject(
            "payload_too_large",
            "payload_exceeds_size_limit",
            {"bytes": int(payload_bytes), "max_bytes": int(max_payload_bytes)},
        )

    def walk(v: Any, depth: int) -> Optional[Tuple[str, Dict[str, Any]]]:
        if depth > int(max_depth):
            return "payload_too_deep", {"max_depth": int(max_depth)}

        if v is None or isinstance(v, (bool, int, float)):
            return None

        if isinstance(v, str):
            b = len(v.encode("utf-8", errors="ignore"))
            if b > int(max_string_bytes):
                return "string_too_large", {"bytes": int(b), "max_bytes": int(max_string_bytes)}
            return None

        if isinstance(v, list):
            if len(v) > int(max_list_len):
                return "list_too_long", {"len": len(v), "max_len": int(max_list_len)}
            for it in v:
                err = walk(it, depth + 1)
                if err:
                    return err
            return None

        if isinstance(v, dict):
            if len(v) > int(max_payload_keys):
                return "object_too_many_keys", {"keys": len(v), "max_keys": int(max_payload_keys)}
            for kk, vv in v.items():
                if not isinstance(kk, str):
                    return "invalid_key_type", {"key_type": str(type(kk))}
                kb = len(kk.encode("utf-8", errors="ignore"))
                if kb > int(max_string_bytes):
                    return "key_too_large", {"bytes": int(kb), "max_bytes": int(max_string_bytes)}
                err = walk(vv, depth + 1)
                if err:
                    return err
            return None

        return "invalid_value_type", {"type": str(type(v))}

    err = walk(payload, 0)
    if err:
        reason, details = err
        return TxVerdict.reject("invalid_payload", reason, details)

    return None


def _validate_payload_mvp(env: TxEnvelope) -> Optional[TxVerdict]:
    p = env.payload or {}
    t = env.tx_type.strip().upper()

    if t == "PEER_ADVERTISE":
        return _require(p, "endpoint")
    if t == "PEER_RENDEZVOUS_TICKET_CREATE":
        return _require(p, "target_peer")
    if t == "PEER_RENDEZVOUS_TICKET_REVOKE":
        return _require(p, "ticket_id")
    if t == "PEER_REQUEST_CONNECT":
        if not p.get("peer_id") and not p.get("ticket_id"):
            return TxVerdict.reject("invalid_payload", "missing_peer_or_ticket", {"payload": p})
        return None
    if t == "PEER_BAN_SET":
        return _require(p, "peer_id")
    if t == "PEER_REPUTATION_SIGNAL":
        return _require(p, "peer_id")

    if t == "VALIDATOR_REGISTER":
        return _require(p, "endpoint")
    if t == "VALIDATOR_SET_UPDATE":
        active = p.get("active_set")
        if not isinstance(active, list) or len(active) == 0:
            return TxVerdict.reject("invalid_payload", "missing_active_set", {"payload": p})
        return None

    return None


def _min_rep_threshold(min_rep: Any) -> Optional[float]:
    if min_rep is None:
        return None
    try:
        if isinstance(min_rep, str):
            min_rep = float(min_rep.strip())
        elif isinstance(min_rep, int):
            min_rep = float(min_rep)
        elif isinstance(min_rep, float):
            pass
        else:
            return None
        if min_rep >= 1.0 and min_rep <= 100.0:
            return min_rep / 100.0
        return float(min_rep)
    except Exception:
        return None


def _canon_parent_requires_env_parent(txdef: Dict[str, Any]) -> bool:
    parent = txdef.get("parent") or txdef.get("parent_types") or txdef.get("parent_types".upper())
    if parent is None:
        return False
    if isinstance(parent, str):
        return bool(parent.strip())
    if isinstance(parent, list):
        return len(parent) > 0
    return False


def _system_signer_from_ledger(ledger: Any) -> str:
    """Return the configured system signer (proposer) if present."""
    try:
        params = getattr(ledger, "params", None)
        if isinstance(params, dict):
            ss = str(params.get("system_signer") or "").strip()
            if ss:
                return ss
    except Exception:
        pass
    return ""


def admit_tx(
    tx: Any = None,
    ledger: Any = None,
    canon: Optional[TxIndex] = None,
    idx: Optional[TxIndex] = None,
    context: str = "mempool",
) -> TxVerdict:
    if canon is None:
        canon = idx
    if canon is None:
        return TxVerdict.reject("invalid_args", "missing_canon", None)

    tx_for_size = _normalize_jsonable(tx)

    max_tx_bytes = _env_int("WEALL_MAX_TX_ENVELOPE_BYTES", 96 * 1024)  # 96 KiB
    env_size = _json_size_bytes(tx_for_size)
    if env_size >= 0 and env_size > int(max_tx_bytes):
        return TxVerdict.reject(
            "tx_too_large",
            "tx_envelope_exceeds_size_limit",
            {"bytes": int(env_size), "max_bytes": int(max_tx_bytes)},
        )

    env = TxEnvelope.from_json(tx)

    if not env.tx_type.strip():
        return TxVerdict.reject("bad_shape", "missing_tx_type", None)
    if not env.signer.strip():
        return TxVerdict.reject("bad_shape", "missing_signer", None)
    if int(env.nonce) < 0:
        return TxVerdict.reject("bad_shape", "nonce_must_be_nonnegative", {"nonce": int(env.nonce)})

    txdef = _get_txdef(canon, env.tx_type)
    if txdef is None:
        return TxVerdict.reject("unknown_tx", "tx_type_not_in_canon", {"tx_type": env.tx_type})

    ctx = str(context or "").strip().lower()
    ctx_base = "mempool" if ctx.startswith("mempool") else ctx

    if ctx_base == "mempool" and bool(txdef.get("receipt_only", False)):
        return TxVerdict.reject("receipt_only", "receipt_only_tx_not_allowed_in_mempool", {"tx_type": env.tx_type})

    canon_ctx = str(txdef.get("context", "") or "").strip().lower()
    if ctx_base == "mempool" and canon_ctx == "block":
        return TxVerdict.reject("block_only", "tx_not_allowed_in_mempool", {"tx_type": env.tx_type})

    payload_verdict = _validate_payload_limits(env.payload)
    if payload_verdict is not None:
        return payload_verdict

    if _env_bool("WEALL_ENFORCE_TX_SCHEMA", False):
        ok_schema, schema_err = validate_payload(env.tx_type, env.payload)
        if not ok_schema:
            return TxVerdict.reject(
                "invalid_payload",
                "schema_validation_failed",
                schema_err if isinstance(schema_err, dict) else {"tx_type": env.tx_type},
            )

    payload_verdict = _validate_payload_mvp(env)
    if payload_verdict is not None:
        return payload_verdict

    if bool(txdef.get("system_only", False)):
        ss = _system_signer_from_ledger(ledger)
        allowed = {"SYSTEM"}
        if ss:
            allowed.add(ss)
        if not (bool(env.system) and str(env.signer) in allowed):
            return TxVerdict.reject(
                "forbidden",
                "system_only_tx_requires_system_signer",
                {"tx_type": env.tx_type, "signer": env.signer, "system": bool(env.system), "allowed": sorted(allowed)},
            )

    if _canon_parent_requires_env_parent(txdef):
        if env.parent is None or not str(env.parent).strip():
            return TxVerdict.reject(
                "invalid_payload",
                "parent_required_by_canon",
                {"tx_type": env.tx_type},
            )

    sys_signer = _system_signer_from_ledger(ledger)
    sys_allowed = {"SYSTEM"}
    if sys_signer:
        sys_allowed.add(sys_signer)
    if bool(env.system) and str(env.signer) in sys_allowed:
        return TxVerdict.admit()

    if (not env.system) and env.signer == "SYSTEM":
        return TxVerdict.reject("gate_denied", "system_flag_required", {"signer": env.signer})

    acct = getattr(ledger, "accounts", {}).get(env.signer) if ledger is not None else None
    if acct is None:
        if env.tx_type.strip().upper() == "ACCOUNT_REGISTER":
            if ctx_base == "mempool" and int(env.nonce) != 1:
                return TxVerdict.reject("bad_nonce", "register_nonce_must_be_one", {"expected": 1, "got": int(env.nonce)})
            return TxVerdict.admit()
        return TxVerdict.reject("unknown_signer", "signer_not_found", {"signer": env.signer})

    if bool(acct.get("banned", False)):
        return TxVerdict.reject("gate_denied", "banned", {"signer": env.signer})
    if bool(acct.get("locked", False)):
        return TxVerdict.reject("gate_denied", "locked", {"signer": env.signer})

    if ctx_base == "mempool":
        expected = int(acct.get("nonce", 0)) + 1

        if ctx == "mempool_future":
            try:
                gap = int(os.environ.get("WEALL_MEMPOOL_MAX_FUTURE_NONCE_GAP", "32"))
            except Exception:
                gap = 32
            got = int(env.nonce)
            if got < expected or got > (expected + max(gap, 0)):
                return TxVerdict.reject("bad_nonce", "nonce_out_of_window", {"expected": expected, "got": got, "max_gap": gap})
        else:
            if int(env.nonce) != expected:
                return TxVerdict.reject("bad_nonce", "nonce_must_be_next", {"expected": expected, "got": env.nonce})

    allow_unsigned = _env_bool("WEALL_ALLOW_UNSIGNED_TXS", False) and _is_unsafe_dev_mode()
    sigverify_enabled = (_env_bool("WEALL_SIGVERIFY", True) or False)
    if not sigverify_enabled and not _is_unsafe_dev_mode():
        sigverify_enabled = True
    if (not env.system) and ledger is not None and sigverify_enabled and (not allow_unsigned):
        ok = verify_tx_signature(
            {
                "accounts": getattr(ledger, "accounts", {}),
                "params": getattr(ledger, "params", {}) if ledger is not None else {},
            },
            env.to_json(),
        )
        if not ok:
            return TxVerdict.reject(
                "bad_sig",
                "signature_verification_failed",
                {"signer": env.signer, "tx_type": env.tx_type},
            )

    if not env.system:
        min_rep = _min_rep_threshold(txdef.get("min_reputation"))
        if min_rep is not None:
            have = acct.get("reputation", 0.0)
            try:
                have_f = float(have)
            except Exception:
                have_f = 0.0
            if have_f < float(min_rep):
                return TxVerdict.reject(
                    "reputation_too_low",
                    "min_reputation_not_met",
                    {"min_reputation": min_rep, "reputation": have_f},
                )
        gate_expr = txdef.get("gate") or txdef.get("subject_gate")
        if gate_expr:
            ok, meta = resolve_signer_authz(
                ledger=ledger,
                signer=env.signer,
                gate_expr=str(gate_expr),
                payload=env.payload,
            )
            if not ok:
                details: Dict[str, Any] = {"gate": gate_expr}
                if isinstance(meta, dict):
                    details.update(meta)
                return TxVerdict.reject("gate_denied", str(details.get("reason", "gate_expr_denied")), details)

    return TxVerdict.admit()


__all__ = ["TxEnvelope", "TxVerdict", "admit_tx"]
