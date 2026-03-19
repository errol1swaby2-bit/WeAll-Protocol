"""Transaction admission (mempool / system queue).

This is the *front door* for transactions before they enter the mempool.
It must be deterministic and cheap.

Unit tests in this repo expect:
  - `admit_tx(...)` can be unpacked as `(ok, rejection)`
  - `ok` is a bool
  - `rejection` exposes `.code` and `.reason` (and optionally `.meta`)
  - `verdict = admit_tx(...)` also supports `.ok`, `.code`, `.reason`, `.details`

The canon/TxIndex used in tests is a lightweight dict-based spec (not the
full YAML tx_canon). This module follows that MVP spec.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from pydantic import ValidationError

from weall.crypto.sig import strict_tx_sig_domain_enabled
from weall.ledger.state import LedgerView
from weall.runtime.account_id import is_valid_account_id, strict_account_ids_enabled
from weall.runtime.gate_expr import eval_gate
from weall.runtime.reputation_units import (
    account_reputation_units,
    threshold_to_units,
    units_to_reputation,
)
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_schema import model_for_tx_type, validate_tx_envelope
from weall.tx.canon import TxIndex

Json = dict[str, Any]


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None:
        return int(default)
    s = str(v).strip()
    if not s:
        return int(default)
    try:
        return int(s)
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _json_bytes(obj: Any) -> int:
    """Deterministic, best-effort size estimate for JSON-like objects."""
    try:
        s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except Exception:
        try:
            s = repr(obj)
        except Exception:
            s = "<unserializable>"
    try:
        return len(s.encode("utf-8"))
    except Exception:
        return len(s)


def _walk_limits(
    obj: Any,
    *,
    max_depth: int,
    max_list_len: int,
    max_dict_keys: int,
    max_str_len: int,
    max_nodes: int,
) -> tuple[str, dict[str, Any]] | None:
    """Validate structure limits (depth, list length, dict keys, string length, nodes).

    Returns (reason, meta) if a limit is exceeded.
    """
    stack: list[tuple[Any, int]] = [(obj, 0)]
    nodes = 0

    while stack:
        cur, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return "payload_nodes_exceeded", {"have": nodes, "limit": max_nodes}

        if depth > max_depth:
            return "payload_depth_exceeded", {"have": depth, "limit": max_depth}

        if cur is None or isinstance(cur, (bool, int)):
            continue

        if isinstance(cur, float):
            return "payload_float_not_allowed", {"value": repr(cur)}

        if isinstance(cur, str):
            if len(cur) > max_str_len:
                return "payload_string_too_long", {"have": len(cur), "limit": max_str_len}
            continue

        if isinstance(cur, (bytes, bytearray)):
            if len(cur) > max_str_len:
                return "payload_bytes_too_long", {"have": len(cur), "limit": max_str_len}
            continue

        if isinstance(cur, list):
            if len(cur) > max_list_len:
                return "payload_list_too_long", {"have": len(cur), "limit": max_list_len}
            for it in cur:
                stack.append((it, depth + 1))
            continue

        if isinstance(cur, dict):
            if len(cur) > max_dict_keys:
                return "payload_object_too_many_keys", {"have": len(cur), "limit": max_dict_keys}
            for k, v in cur.items():
                if isinstance(k, str) and len(k) > max_str_len:
                    return "payload_key_too_long", {"have": len(k), "limit": max_str_len}
                stack.append((v, depth + 1))
            continue

        return "payload_non_json_type", {"type": type(cur).__name__}

    return None


def _payload_limits_ok(env: TxEnvelope, spec: Json) -> AdmissionVerdict | None:
    """Cheap structural + size caps for payload hardening."""
    payload = env.payload or {}

    max_payload_bytes = int(
        spec.get("max_payload_bytes") or _env_int("WEALL_MAX_TX_PAYLOAD_BYTES", 64 * 1024)
    )
    max_payload_bytes = max(1024, max_payload_bytes)

    max_depth = int(spec.get("max_payload_depth") or _env_int("WEALL_MAX_TX_PAYLOAD_DEPTH", 20))
    max_depth = max(4, max_depth)

    max_list_len = int(
        spec.get("max_payload_list_len") or _env_int("WEALL_MAX_TX_PAYLOAD_LIST_LEN", 2000)
    )
    max_list_len = max(16, max_list_len)

    max_dict_keys = int(
        spec.get("max_payload_dict_keys") or _env_int("WEALL_MAX_TX_PAYLOAD_DICT_KEYS", 2000)
    )
    max_dict_keys = max(16, max_dict_keys)

    max_str_len = int(
        spec.get("max_payload_str_len") or _env_int("WEALL_MAX_TX_PAYLOAD_STR_LEN", 64 * 1024)
    )
    max_str_len = max(256, max_str_len)

    max_nodes = int(spec.get("max_payload_nodes") or _env_int("WEALL_MAX_TX_PAYLOAD_NODES", 50_000))
    max_nodes = max(1_000, max_nodes)

    wl = _walk_limits(
        payload,
        max_depth=max_depth,
        max_list_len=max_list_len,
        max_dict_keys=max_dict_keys,
        max_str_len=max_str_len,
        max_nodes=max_nodes,
    )
    if wl is not None:
        reason, meta = wl
        return _rej("invalid_payload", reason, **meta)

    size = _json_bytes(payload)
    if size > max_payload_bytes:
        return _rej(
            "payload_too_large", "payload_bytes_exceeded", have=size, limit=max_payload_bytes
        )

    return None


@dataclass(frozen=True)
class AdmissionRejection:
    code: str
    reason: str = ""
    meta: Json = None  # type: ignore[assignment]

    def to_json(self) -> Json:
        out: Json = {"code": self.code}
        if self.reason:
            out["reason"] = self.reason
        if self.meta:
            out["meta"] = self.meta
        return out


@dataclass(frozen=True)
class AdmissionVerdict:
    ok: bool
    rejection: AdmissionRejection | None = None

    def __iter__(self) -> Iterable[Any]:
        yield self.ok
        yield self.rejection

    @property
    def code(self) -> str:
        return "" if self.ok or not self.rejection else self.rejection.code

    @property
    def reason(self) -> str:
        return "" if self.ok or not self.rejection else self.rejection.reason

    @property
    def details(self) -> Json:
        return (
            {} if self.ok or not self.rejection or not self.rejection.meta else self.rejection.meta
        )


def _rej(code: str, reason: str = "", **meta: Any) -> AdmissionVerdict:
    return AdmissionVerdict(False, AdmissionRejection(code=code, reason=reason, meta=meta or {}))


def _as_ledgerview(ledger: Any) -> LedgerView:
    if isinstance(ledger, LedgerView):
        return ledger
    if isinstance(ledger, dict):
        return LedgerView.from_ledger(ledger)
    raise TypeError(f"ledger must be LedgerView|dict, got {type(ledger).__name__}")


def _required(payload: Json, fields: tuple[str, ...]) -> str | None:
    for f in fields:
        if payload.get(f) in (None, "", [], {}):
            return f
    return None


def _mvp_payload_checks(env: TxEnvelope) -> AdmissionVerdict | None:
    p = env.payload or {}
    t = env.tx_type.upper()

    if t == "PEER_ADVERTISE":
        miss = _required(p, ("endpoint",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "PEER_RENDEZVOUS_TICKET_CREATE":
        miss = _required(p, ("target_peer",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "PEER_RENDEZVOUS_TICKET_REVOKE":
        miss = _required(p, ("ticket_id",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "PEER_REQUEST_CONNECT":
        if not p.get("peer_id") and not p.get("ticket_id"):
            return _rej(
                "invalid_payload", "missing:peer_id_or_ticket_id", field="peer_id_or_ticket_id"
            )

    if t == "PEER_BAN_SET":
        miss = _required(p, ("peer_id",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "PEER_REPUTATION_SIGNAL":
        miss = _required(p, ("peer_id",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "VALIDATOR_REGISTER":
        miss = _required(p, ("endpoint",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "VALIDATOR_HEARTBEAT":
        miss = _required(p, ("node_id",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "VALIDATOR_SET_UPDATE":
        miss = _required(p, ("active_set",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "VALIDATOR_SET":
        miss = _required(p, ("validators",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    if t == "VALIDATOR_BAN_SET":
        miss = _required(p, ("validator",))
        return _rej("invalid_payload", f"missing:{miss}", field=miss) if miss else None

    return None


def _should_apply_account_semantics(signer: str) -> bool:
    s = str(signer or "").strip()
    if not s:
        return False

    if strict_account_ids_enabled():
        return is_valid_account_id(s)

    return s.startswith("@")


def _nonce_ok(env: TxEnvelope, ledger: LedgerView) -> AdmissionVerdict | None:
    signer = env.signer or ""
    if not _should_apply_account_semantics(signer):
        return None

    acct = (ledger.accounts or {}).get(signer) or {}
    current = int(acct.get("nonce") or 0)
    expected = current + 1

    if int(env.nonce) != expected:
        return _rej("bad_nonce", f"expected:{expected}", expected=expected, got=int(env.nonce))
    return None


def _min_reputation_units(spec: Json) -> int | None:
    raw_units = spec.get("min_reputation_milli")
    if raw_units is not None:
        try:
            return max(0, int(raw_units))
        except Exception:
            return 0

    raw = spec.get("min_reputation")
    if raw is None:
        return None

    try:
        raw_dec = Decimal(str(raw).strip())
    except Exception:
        raw_dec = Decimal(0)

    if Decimal(1) <= raw_dec <= Decimal(100):
        normalized = raw_dec / Decimal(100)
    else:
        normalized = raw_dec
    return max(0, threshold_to_units(str(normalized), default=0))


def _reputation_and_flags_ok(
    env: TxEnvelope, ledger: LedgerView, spec: Json
) -> AdmissionVerdict | None:
    signer = env.signer or ""
    if not _should_apply_account_semantics(signer):
        return None

    acct = (ledger.accounts or {}).get(signer) or {}

    if acct.get("banned") is True:
        return _rej("gate_denied", "banned")

    if acct.get("locked") is True:
        return _rej("gate_denied", "locked")

    min_rep_units = _min_reputation_units(spec)
    if min_rep_units is not None:
        rep_units = account_reputation_units(acct, default=0)
        if rep_units < min_rep_units:
            return _rej(
                "gate_denied",
                "min_reputation",
                min_reputation_milli=int(min_rep_units),
                min_reputation=units_to_reputation(min_rep_units),
                reputation_milli=int(rep_units),
                reputation=units_to_reputation(rep_units),
            )

    return None


def _bootstrap_open_gate_bypass(env: TxEnvelope, spec: Json) -> bool:
    """
    Dev/testnet escape hatch for POH bootstrap.

    Canon marks POH_BOOTSTRAP_TIER3_GRANT with a Validator subject gate and
    SYSTEM origin. In dev/testnet, when WEALL_POH_BOOTSTRAP_OPEN=1, we
    intentionally allow a freshly registered user account to submit this tx so
    local operators can run the full golden path without pre-seeding a validator
    identity or system signer plumbing.

    Apply-time system-only bypass already exists in domain_dispatch.py; this
    mirrors that behavior at admission-time for the subject gate only.
    """
    tx_type = str(env.tx_type or "").strip().upper()
    gate = str(spec.get("subject_gate") or "").strip()
    if tx_type != "POH_BOOTSTRAP_TIER3_GRANT":
        return False
    if gate != "Validator":
        return False
    if str(os.environ.get("WEALL_POH_BOOTSTRAP_OPEN") or "").strip() != "1":
        return False
    mode = str(os.environ.get("WEALL_MODE") or "prod").strip().lower()
    return mode in {"dev", "testnet"}


def _gate_ok(env: TxEnvelope, ledger: LedgerView, spec: Json) -> AdmissionVerdict | None:
    gate = str(spec.get("subject_gate") or "").strip()
    if not gate:
        return None

    if _bootstrap_open_gate_bypass(env, spec):
        return None

    ok, meta = eval_gate(
        signer=env.signer or "", state=ledger, expr=gate, payload=env.payload or {}
    )
    if not ok:
        return _rej("gate_denied", f"gate:{gate}", gate=gate, gate_meta=meta)
    return None


def _tx_sigverify_enforced() -> bool:
    mode = _mode()
    override = os.environ.get("WEALL_SIGVERIFY")

    if mode == "prod":
        return True
    if override is None:
        return False
    return bool(str(override).strip() == "1")


def _sig_ok(env: TxEnvelope, *, context: str) -> AdmissionVerdict | None:
    """Enforce *presence* of a signature for untrusted ingress contexts.

    Policy:
      - context in {mempool, local, block}: signature presence is NOT enforced here.
        Block-context cryptographic verification is handled separately by
        `_block_sig_verify_ok(...)` so block validity does not rely on public
        ingress checks.
      - context in {gossip, peer, http}: required when WEALL_SIGVERIFY=1 (or default-prod behavior).
    """
    ctx = (context or "").strip().lower() or "mempool"

    # Local/deterministic paths: presence-only checks are handled elsewhere.
    if ctx in {"mempool", "local", "block"}:
        return None

    # If a signature is present, let it through.
    if str(env.sig or "").strip():
        return None

    if not _tx_sigverify_enforced():
        return None

    return _rej("missing_sig", "sig_required")


def _block_sig_verify_ok(env: TxEnvelope, ledger: LedgerView) -> AdmissionVerdict | None:
    """Verify non-system tx signatures during block validation.

    Block validity must not depend on local mempool/HTTP ingress assumptions.
    Every non-system tx carried by a committed block must be self-authenticating
    from the block payload alone.

    Policy:
      - SYSTEM txs remain exempt because they are authorized by protocol/block context.
      - non-system txs must carry a non-empty signature in all modes.
      - when the strict replay domain is enabled, non-system txs must also carry
        an explicit chain_id that matches the signed message domain.
    """
    signer = str(env.signer or "").strip()
    if not signer:
        return _rej("invalid_tx", "missing_signer")

    if signer == "SYSTEM" or bool(getattr(env, "system", False)):
        return None

    sig = str(getattr(env, "sig", "") or "").strip()
    if not sig:
        return _rej("missing_sig", "sig_required_in_block")

    txj = env.to_json()
    tx_chain_id = str(txj.get("chain_id") or "").strip()
    if strict_tx_sig_domain_enabled() and not tx_chain_id:
        return _rej("missing_chain_id", "chain_id_required_in_block")

    state = ledger.to_ledger()
    if not verify_tx_signature(state if isinstance(state, dict) else {}, txj):
        return _rej("bad_sig", "signature_verification_failed")

    return None


def admit_tx(
    tx: Json | TxEnvelope,
    ledger: LedgerView | Json,
    canon: TxIndex | None = None,
    context: str = "mempool",
) -> AdmissionVerdict:
    lv = _as_ledgerview(ledger)
    env = TxEnvelope.from_json(tx)

    if not env.tx_type:
        return _rej("invalid_tx", "missing_tx_type")
    if not env.signer:
        return _rej("invalid_tx", "missing_signer")

    ctx = str(context or "").strip().lower() or "mempool"

    # Keep SYSTEM txs out of public ingress.
    if ctx in {"mempool", "gossip", "peer"}:
        if str(env.signer).strip() == "SYSTEM" or bool(getattr(env, "system", False)):
            return _rej(
                "system_tx_forbidden",
                "system_only_tx_not_allowed_in_public_ingress",
                tx_type=str(env.tx_type),
                signer=str(env.signer),
            )

    if strict_account_ids_enabled() and not is_valid_account_id(env.signer):
        return _rej("invalid_tx", "bad_signer_format", signer=str(env.signer))

    if canon is None:
        spec = {}
    else:
        try:
            spec = canon.get(env.tx_type.upper(), {})
        except Exception:
            spec = {}

    bad = _payload_limits_ok(env, spec)
    if bad is not None:
        return bad

    # Strict schema validation for modeled tx types (public-ish ingress + block validation).
    if ctx in {"mempool", "gossip", "peer", "block"}:
        try:
            if model_for_tx_type(env.tx_type.upper()) is not None:
                raw = tx if isinstance(tx, dict) else env.to_json()
                validate_tx_envelope(raw)
        except ValidationError as ve:
            return _rej("invalid_payload", "schema_validation_failed", errors=ve.errors())
        except Exception:
            return _rej("invalid_payload", "schema_validation_error")

    bad = _mvp_payload_checks(env)
    if bad is not None:
        return bad

    bad = _sig_ok(env, context=ctx)
    if bad is not None:
        return bad

    if ctx == "block":
        bad = _block_sig_verify_ok(env, lv)
        if bad is not None:
            return bad

    bad = _nonce_ok(env, lv)
    if bad is not None:
        return bad

    bad = _reputation_and_flags_ok(env, lv, spec)
    if bad is not None:
        return bad

    bad = _gate_ok(env, lv, spec)
    if bad is not None:
        return bad

    return AdmissionVerdict(True, None)


TxVerdict = AdmissionVerdict
TxRejection = AdmissionRejection

__all__ = [
    "TxEnvelope",
    "TxVerdict",
    "TxRejection",
    "AdmissionVerdict",
    "AdmissionRejection",
    "admit_tx",
]
