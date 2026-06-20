from __future__ import annotations

import contextlib
import fcntl
import hmac
import ipaddress
import json
import os
import time
import threading
from pathlib import Path
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from fastapi import APIRouter, Request
from pydantic import ValidationError

from weall.api.errors import ApiError
from weall.api.public_seed_registry import (
    PublicSeedRegistryError,
    load_public_seed_registry,
    public_seed_registry_path,
    public_testnet_enabled,
    verified_tx_upstreams_from_registry,
)
from weall.api.routes_public_parts.common import (
    _executor,
    _mempool,
    _read_json_limited,
    _require_registered_signer_for_user_tx,
    _snapshot,
)
from weall.ledger.state import LedgerView
from weall.crypto.sig import strict_tx_sig_domain_enabled
from weall.runtime.mempool import compute_tx_id
from weall.runtime.sigverify import verify_tx_signature
from weall.runtime.tx_schema import validate_tx_envelope

router = APIRouter()

Json = dict[str, Any]

_OUTBOX_AUTODRAIN_LOCK = threading.Lock()
_OUTBOX_AUTODRAIN_STOP: threading.Event | None = None
_OUTBOX_AUTODRAIN_THREAD: threading.Thread | None = None


_TX_PUBLIC_ENTRYPOINTS: dict[str, list[str]] = {
    "BLOCK_ATTEST": ["/v1/consensus/attest/submit"],
    "POH_CHALLENGE_OPEN": ["/v1/poh/challenge/tx/open", "/v1/tx/submit"],
    "POH_TIER2_REQUEST_OPEN": ["/v1/tx/submit"],
    "POH_LIVE_REQUEST_OPEN": ["/v1/poh/live/tx/request", "/v1/tx/submit"],
    "POH_TIER2_JUROR_ACCEPT": ["/v1/tx/submit"],
    "POH_TIER2_JUROR_DECLINE": ["/v1/tx/submit"],
    "POH_TIER2_REVIEW_SUBMIT": ["/v1/tx/submit"],
    "POH_LIVE_JUROR_ACCEPT": ["/v1/poh/live/tx/juror-accept", "/v1/tx/submit"],
    "POH_LIVE_JUROR_DECLINE": ["/v1/poh/live/tx/juror-decline", "/v1/tx/submit"],
    "POH_LIVE_ATTENDANCE_MARK": ["/v1/poh/live/tx/attendance", "/v1/tx/submit"],
    "POH_LIVE_VERDICT_SUBMIT": ["/v1/poh/live/tx/verdict", "/v1/tx/submit"],
}


def _default_public_entrypoints(origin: str, context: str) -> list[str]:
    origin_norm = str(origin or "").strip().upper()
    context_norm = str(context or "").strip().lower()
    routes: list[str] = []
    if context_norm == "mempool" and origin_norm in {"USER", "VALIDATOR"}:
        routes.append("/v1/tx/submit")
        routes.append("/v1/mempool/submit")
    return routes


def _tx_public_entrypoints(tx_type: str, origin: str, context: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for route in _TX_PUBLIC_ENTRYPOINTS.get(str(tx_type or "").strip(), []) + _default_public_entrypoints(origin, context):
        norm = str(route or "").strip()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        ordered.append(norm)
    return ordered


def _mode() -> str:
    return (os.environ.get("WEALL_MODE") or "prod").strip().lower() or "prod"


def _safe_mempool(request: Request):
    try:
        return _mempool(request)
    except Exception:
        return None


def _safe_executor(request: Request):
    try:
        return _executor(request)
    except Exception:
        return None


def _net_node(request: Request):
    return getattr(request.app.state, "net_node", None)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return str(raw).strip() in {"1", "true", "TRUE", "yes", "YES", "on", "ON"}


def _env_int_safe(name: str, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(str(raw).strip()) if raw is not None and str(raw).strip() else int(default)
    except Exception:
        value = int(default)
    value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value


def _observer_edge_mode() -> bool:
    if _env_bool("WEALL_OBSERVER_EDGE_MODE", False):
        return True
    lifecycle = str(os.environ.get("WEALL_NODE_LIFECYCLE_STATE") or "").strip().lower()
    return lifecycle in {"observer_onboarding", "bootstrap_registration"} and _env_bool(
        "WEALL_OBSERVER_MODE", False
    )


def _normalized_tx_upstream_urls(request: Request | None = None) -> list[str]:
    """Return configured or verified public tx upstream API bases.

    A local observer edge node may accept signed user txs from its local
    frontend, then forward the identical envelope to genesis or another upstream
    peer.  This helper is intentionally explicit: no upstream is inferred from a
    generic frontend API base that might point back to the local observer.
    """

    raw = str(os.environ.get("WEALL_TX_UPSTREAM_URLS") or "").strip()
    if not raw and _observer_edge_mode():
        raw = str(
            os.environ.get("WEALL_GENESIS_API_BASE")
            or os.environ.get("WEALL_BOOTSTRAP_API_BASE")
            or os.environ.get("WEALL_BOOTSTRAP_URL")
            or ""
        ).strip()
    max_upstreams = _env_int_safe("WEALL_TX_UPSTREAM_MAX_TARGETS", 4, minimum=1, maximum=16)

    if not raw and public_testnet_enabled():
        cfg = getattr(request.app.state, "cfg", None) if request is not None else None
        try:
            registry = load_public_seed_registry(
                public_seed_registry_path(getattr(cfg, "public_seed_registry_path", None) if cfg is not None else None)
            )
            derived = verified_tx_upstreams_from_registry(registry)[:max_upstreams]
            raw = ",".join(derived)
        except PublicSeedRegistryError:
            raw = ""

    if not raw:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for item in raw.replace("\n", ",").split(","):
        base = str(item or "").strip().rstrip("/")
        if not base:
            continue
        try:
            parsed = urllib.parse.urlparse(base)
        except Exception:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if parsed.query or parsed.fragment:
            continue
        norm = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
        if len(out) >= max_upstreams:
            break
    return out


def _redact_upstream_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(str(url or ""))
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port is not None else ""
        path = parsed.path.rstrip("/")
        return urllib.parse.urlunparse((parsed.scheme, f"{host}{port}", path, "", "", ""))
    except Exception:
        return "<invalid>"


def _forward_tx_to_upstream(url: str, body: Json, *, tx_id: str, timeout_s: int) -> Json:
    expected_chain_id = str(body.get("chain_id") or "").strip() if isinstance(body, dict) else ""
    identity = _verify_upstream_identity(url, expected_chain_id=expected_chain_id, timeout_s=timeout_s)
    if not bool(identity.get("ok")):
        return {"ok": False, "error": str(identity.get("error") or "upstream_identity_failed"), "identity": identity, "upstream": _redact_upstream_url(url)}

    target = f"{str(url).rstrip('/')}/v1/tx/submit"
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        target,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-WeAll-Observer-Forwarded": "1",
            "X-WeAll-Client-Tx-Id": str(tx_id or ""),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=int(timeout_s)) as resp:  # noqa: S310 - explicit operator-configured upstream
            raw = resp.read(1024 * 1024)
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            ok = bool(isinstance(parsed, dict) and parsed.get("ok"))
            upstream_tx_id = str(parsed.get("tx_id") or "") if isinstance(parsed, dict) else ""
            if ok and upstream_tx_id and upstream_tx_id != str(tx_id):
                return {
                    "ok": False,
                    "error": "upstream_tx_id_mismatch",
                    "status": str(parsed.get("status") or "accepted") if isinstance(parsed, dict) else "unknown",
                    "tx_id": upstream_tx_id,
                    "expected_tx_id": str(tx_id),
                    "identity": identity,
                    "upstream": _redact_upstream_url(url),
                }
            return {
                "ok": ok,
                "status": str(parsed.get("status") or "accepted") if isinstance(parsed, dict) else "unknown",
                "tx_id": upstream_tx_id,
                "identity": identity,
                "upstream": _redact_upstream_url(url),
            }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(4096)
            detail = raw.decode("utf-8", errors="replace")[:512]
        except Exception:
            detail = ""
        return {
            "ok": False,
            "error": "upstream_http_error",
            "status_code": int(getattr(exc, "code", 0) or 0),
            "detail": detail,
            "identity": identity,
            "upstream": _redact_upstream_url(url),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
            "detail": str(exc)[:256],
            "identity": identity,
            "upstream": _redact_upstream_url(url),
        }


def _propagate_tx_to_configured_upstreams(request: Request, body: Json, *, tx_id: str) -> Json:
    if str(request.headers.get("x-weall-observer-forwarded") or "").strip() == "1":
        return {"attempted": False, "accepted": False, "skipped": "already_forwarded", "results": []}

    urls = _normalized_tx_upstream_urls(request)
    if not urls:
        skipped = "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM" if public_testnet_enabled() else "no_upstreams_configured"
        return {"attempted": False, "accepted": False, "skipped": skipped, "error": skipped, "results": []}

    timeout_s = _env_int_safe("WEALL_TX_UPSTREAM_TIMEOUT_S", 5, minimum=1, maximum=60)
    results = [_forward_tx_to_upstream(url, body, tx_id=tx_id, timeout_s=timeout_s) for url in urls]
    accepted = any(bool(r.get("ok")) for r in results if isinstance(r, dict))
    return {"attempted": True, "accepted": bool(accepted), "results": results}


def _tx_upstream_required() -> bool:
    return _env_bool("WEALL_TX_UPSTREAM_REQUIRED", False)


def _observer_edge_operator_auth_enabled() -> bool:
    return _env_bool("WEALL_OBSERVER_EDGE_OPERATOR_AUTH", True)


def _request_is_loopback(request: Request) -> bool:
    host = ""
    try:
        host = str(request.client.host or "") if request.client else ""
    except Exception:
        host = ""
    if host.lower() in {"localhost"}:
        return True
    try:
        return bool(ipaddress.ip_address(host).is_loopback)
    except Exception:
        return False


def _require_observer_edge_operator(request: Request) -> None:
    if not _observer_edge_operator_auth_enabled():
        return
    if _request_is_loopback(request) and not _env_bool("WEALL_OBSERVER_EDGE_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL", False):
        return
    want = str(os.environ.get("WEALL_OPERATOR_TOKEN") or os.environ.get("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN") or "").strip()
    if not want:
        raise ApiError.forbidden(
            "observer_edge_operator_token_required",
            "observer edge operator endpoints require WEALL_OPERATOR_TOKEN or WEALL_OBSERVER_EDGE_OPERATOR_TOKEN",
            {},
        )
    got = str(request.headers.get("X-WeAll-Operator-Token") or request.headers.get("X-WeAll-Observer-Operator-Token") or "").strip()
    if not got or not hmac.compare_digest(got, want):
        raise ApiError.forbidden("forbidden", "bad_observer_edge_operator_token", {})


def _now_ms() -> int:
    return int(time.time() * 1000)


def _tx_outbox_path() -> Path:
    raw = str(os.environ.get("WEALL_TX_OUTBOX_PATH") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(os.environ.get("WEALL_RUNTIME_DIR") or "data") / "observer_tx_outbox.json"


@contextlib.contextmanager
def _tx_outbox_lock():
    """Serialize observer outbox read/modify/write cycles.

    The observer outbox is intentionally a small local durability queue, not
    consensus state.  A file lock is sufficient for the single-machine observer
    edge posture and prevents concurrent frontend submissions from racing the
    JSON file.  The lock file itself is not secret and may live beside the
    outbox.
    """

    path = _tx_outbox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _quarantine_corrupt_outbox(path: Path, reason: str) -> None:
    try:
        if not path.exists():
            return
        suffix = f".corrupt.{_now_ms()}"
        bad = path.with_suffix(path.suffix + suffix)
        os.replace(path, bad)
    except Exception:
        # Startup/read paths must not crash just because a diagnostic quarantine
        # failed.  Returning an empty queue is fail-closed: nothing is treated as
        # propagated unless it is present and well-formed.
        return


def _load_tx_outbox_unlocked(*, quarantine_corrupt: bool = True) -> list[Json]:
    path = _tx_outbox_path()
    try:
        raw_text = path.read_text(encoding="utf-8")
        raw = json.loads(raw_text)
    except FileNotFoundError:
        return []
    except Exception:
        if quarantine_corrupt:
            _quarantine_corrupt_outbox(path, "json_parse_failed")
        return []
    rows = raw.get("records") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        if quarantine_corrupt:
            _quarantine_corrupt_outbox(path, "bad_shape")
        return []
    return [r for r in rows if isinstance(r, dict)]


def _outbox_created_ms(rec: Json) -> int:
    try:
        return int(rec.get("created_ms") or rec.get("updated_ms") or 0)
    except Exception:
        return 0


def _prune_tx_outbox_rows(rows: list[Json]) -> list[Json]:
    now = _now_ms()
    ttl_ms = _env_int_safe("WEALL_TX_OUTBOX_TTL_MS", 7 * 24 * 60 * 60 * 1000, minimum=60_000, maximum=365 * 24 * 60 * 60 * 1000)
    confirmed_ttl_ms = _env_int_safe("WEALL_TX_OUTBOX_CONFIRMED_TTL_MS", 24 * 60 * 60 * 1000, minimum=60_000, maximum=365 * 24 * 60 * 60 * 1000)
    max_records = _env_int_safe("WEALL_TX_OUTBOX_MAX_RECORDS", 5000, minimum=1, maximum=50000)
    max_bytes = _env_int_safe("WEALL_TX_OUTBOX_MAX_BYTES", 10 * 1024 * 1024, minimum=64 * 1024, maximum=1024 * 1024 * 1024)

    kept: list[Json] = []
    for rec in rows:
        if not isinstance(rec, dict):
            continue
        tx_id = str(rec.get("tx_id") or "").strip()
        if not tx_id:
            continue
        status = str(rec.get("upstream_status") or "pending").strip() or "pending"
        created_ms = _outbox_created_ms(rec)
        updated_ms = int(rec.get("updated_ms") or created_ms or now)
        envelope = rec.get("envelope") if isinstance(rec.get("envelope"), dict) else {}
        expires_ms = 0
        try:
            expires_ms = int(envelope.get("expires_ms") or 0) if isinstance(envelope, dict) else 0
        except Exception:
            expires_ms = 0
        if expires_ms and expires_ms < now and status not in {"confirmed"}:
            continue
        if status == "confirmed" and updated_ms and now - updated_ms > confirmed_ttl_ms:
            continue
        if created_ms and now - created_ms > ttl_ms and status not in {"accepted", "confirmed"}:
            continue
        kept.append(rec)

    kept.sort(key=_outbox_created_ms, reverse=True)
    kept = kept[:max_records]

    # Enforce a coarse disk budget. Prefer dropping oldest confirmed records,
    # then oldest pending/accepted records if the file is still oversized.
    def _size(rs: list[Json]) -> int:
        try:
            return len(json.dumps({"version": 2, "records": rs}, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        except Exception:
            return max_bytes + 1

    if _size(kept) > max_bytes:
        kept.sort(key=lambda r: (0 if str(r.get("upstream_status") or "") == "confirmed" else 1, _outbox_created_ms(r)))
        while kept and _size(kept) > max_bytes:
            kept.pop(0)
    kept.sort(key=_outbox_created_ms)
    return kept


def _write_tx_outbox_unlocked(rows: list[Json]) -> None:
    path = _tx_outbox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = _prune_tx_outbox_rows(rows)
    payload = {"version": 2, "records": rows}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _read_tx_outbox() -> list[Json]:
    with _tx_outbox_lock():
        rows = _load_tx_outbox_unlocked()
        pruned = _prune_tx_outbox_rows(rows)
        if len(pruned) != len(rows):
            _write_tx_outbox_unlocked(pruned)
        return [dict(r) for r in pruned]


def _read_tx_outbox_best_effort() -> list[Json]:
    """Read observer outbox for public status paths without crashing.

    The observer tx outbox is local diagnostic/propagation state, not consensus
    state. Public tx-status must remain read-only-safe even when a deployment
    runs with a read-only application tree or the outbox path is unavailable.
    In that case, fail closed by reporting no local outbox record.
    """
    try:
        return _read_tx_outbox()
    except OSError:
        return []


def _write_tx_outbox(rows: list[Json]) -> None:
    with _tx_outbox_lock():
        _write_tx_outbox_unlocked(rows)


def _outbox_record_for(rows: list[Json], tx_id: str) -> Json | None:
    want = str(tx_id or "").strip()
    for rec in rows:
        if str(rec.get("tx_id") or "").strip() == want:
            return rec
    return None


def _outbox_counts(rows: list[Json]) -> Json:
    counts: dict[str, int] = {}
    for rec in rows:
        status = str(rec.get("upstream_status") or rec.get("status") or "pending").strip() or "pending"
        counts[status] = int(counts.get(status, 0)) + 1
    return counts


def _compact_tx_outbox_result(value: Any, *, _depth: int = 0) -> Json:
    """Return a bounded, non-recursive observer outbox diagnostic result.

    Outbox records are operator diagnostics, not consensus state.  They should
    help explain whether an upstream accepted/confirmed a tx without embedding
    previous outbox summaries recursively inside later status probes.
    """

    if _depth > 2:
        return {"truncated": True, "reason": "max_depth"}
    if not isinstance(value, dict):
        return {}

    def _one(item: Any) -> Json:
        if not isinstance(item, dict):
            return {}
        out: Json = {}
        for key in (
            "ok",
            "attempted",
            "accepted",
            "status",
            "error",
            "tx_id",
            "expected_tx_id",
            "tx_type",
            "signer",
            "height",
            "block_id",
            "included_ts_ms",
            "upstream",
            "local_state_synced",
            "confirmed_height",
            "confirmed_block_id",
        ):
            if key in item:
                out[key] = item.get(key)
        # Deliberately omit nested outbound_propagation/last_result trees.
        return out

    out: Json = {}
    for key in ("attempted", "accepted", "skipped", "queued", "error", "status"):
        if key in value:
            out[key] = value.get(key)
    if isinstance(value.get("results"), list):
        rows = [_one(item) for item in value.get("results", [])[:10]]
        out["results"] = [row for row in rows if row]
        out["result_count"] = len(value.get("results", []))
    if isinstance(value.get("status_reconciliation"), list):
        rows = [_one(item) for item in value.get("status_reconciliation", [])[:10]]
        out["status_reconciliation"] = [row for row in rows if row]
        out["status_reconciliation_count"] = len(value.get("status_reconciliation", []))
    return out


def _enqueue_tx_outbox(body: Json, *, tx_id: str, chain_id: str, request: Request | None = None) -> Json:
    with _tx_outbox_lock():
        rows = _load_tx_outbox_unlocked()
        now = _now_ms()
        rec = _outbox_record_for(rows, tx_id)
        urls = [_redact_upstream_url(u) for u in _normalized_tx_upstream_urls(request)]
        if rec is None:
            rec = {
                "tx_id": str(tx_id),
                "chain_id": str(chain_id or ""),
                "envelope": body,
                "created_ms": now,
                "updated_ms": now,
                "attempts": 0,
                "upstream_status": "pending",
                "upstreams": urls,
                "last_result": {},
            }
            rows.append(rec)
        else:
            rec.setdefault("envelope", body)
            rec["updated_ms"] = now
            rec["upstreams"] = urls
        _write_tx_outbox_unlocked(rows)
        return dict(rec)


def _update_tx_outbox_record(tx_id: str, updates: Json) -> Json:
    with _tx_outbox_lock():
        rows = _load_tx_outbox_unlocked()
        rec = _outbox_record_for(rows, tx_id)
        if rec is None:
            rec = {"tx_id": str(tx_id), "created_ms": _now_ms()}
            rows.append(rec)
        safe_updates = dict(updates)
        if "last_result" in safe_updates:
            safe_updates["last_result"] = _compact_tx_outbox_result(safe_updates.get("last_result"))
        if "last_status_probe" in safe_updates and isinstance(safe_updates.get("last_status_probe"), list):
            safe_updates["last_status_probe"] = [
                _compact_tx_outbox_result(item) if isinstance(item, dict) else {}
                for item in safe_updates.get("last_status_probe", [])[:10]
            ]
        rec.update(safe_updates)
        rec["updated_ms"] = _now_ms()
        _write_tx_outbox_unlocked(rows)
        return dict(rec)


def _tx_upstream_verify_identity_enabled() -> bool:
    return _env_bool("WEALL_TX_UPSTREAM_VERIFY_IDENTITY", True)


def _tx_upstream_require_manifest() -> bool:
    return _env_bool("WEALL_TX_UPSTREAM_REQUIRE_MANIFEST", True)




def _upstream_operator_headers() -> dict[str, str]:
    token = str(
        os.environ.get("WEALL_TX_UPSTREAM_OPERATOR_TOKEN")
        or os.environ.get("WEALL_STATE_SYNC_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OPERATOR_TOKEN")
        or ""
    ).strip()
    if not token:
        return {}
    return {
        "X-WeAll-Operator-Token": token,
        "X-WeAll-State-Sync-Operator-Token": token,
        "X-WeAll-Observer-Operator-Token": token,
    }

def _upstream_get_json(url: str, path: str, *, timeout_s: int) -> Json:
    target = f"{str(url).rstrip('/')}{path}"
    headers = {"Accept": "application/json", "X-WeAll-Observer-Forwarded": "1"}
    headers.update(_upstream_operator_headers())
    req = urllib.request.Request(target, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=int(timeout_s)) as resp:  # noqa: S310 - operator-configured upstream
        raw = resp.read(1024 * 1024)
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(parsed, dict):
            raise ValueError("bad_upstream_json_shape")
        return parsed


def _upstream_post_json(url: str, path: str, payload: Json, *, timeout_s: int) -> Json:
    target = f"{str(url).rstrip('/')}{path}"
    raw_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        target,
        data=raw_payload,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-WeAll-Observer-Forwarded": "1",
            **_upstream_operator_headers(),
        },
    )
    with urllib.request.urlopen(req, timeout=int(timeout_s)) as resp:  # noqa: S310 - operator-configured upstream
        raw = resp.read(16 * 1024 * 1024)
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(parsed, dict):
            raise ValueError("bad_upstream_json_shape")
        return parsed


def _verify_upstream_identity(url: str, *, expected_chain_id: str, timeout_s: int) -> Json:
    if not _tx_upstream_verify_identity_enabled():
        return {"ok": True, "skipped": "identity_verification_disabled", "upstream": _redact_upstream_url(url)}
    expected = str(expected_chain_id or "").strip()
    if not expected:
        return {"ok": False, "error": "missing_expected_chain_id", "upstream": _redact_upstream_url(url)}
    try:
        identity = _upstream_get_json(url, "/v1/chain/identity", timeout_s=timeout_s)
    except Exception as exc:
        return {"ok": False, "error": "upstream_identity_unreachable", "detail": str(exc)[:256], "upstream": _redact_upstream_url(url)}
    observed_chain = str(identity.get("chain_id") or "").strip()
    if observed_chain != expected:
        return {
            "ok": False,
            "error": "upstream_chain_id_mismatch",
            "expected_chain_id": expected,
            "chain_id": observed_chain,
            "upstream": _redact_upstream_url(url),
        }

    manifest_result: Json = {"checked": False}
    if _tx_upstream_require_manifest():
        try:
            manifest = _upstream_get_json(url, "/v1/chain/manifest", timeout_s=timeout_s)
        except Exception as exc:
            return {"ok": False, "error": "upstream_manifest_unreachable", "detail": str(exc)[:256], "upstream": _redact_upstream_url(url)}
        manifest_obj = manifest.get("manifest") if isinstance(manifest.get("manifest"), dict) else {}
        manifest_chain = str(
            manifest.get("chain_id")
            or manifest_obj.get("chain_id")
            or manifest.get("chainId")
            or manifest_obj.get("chainId")
            or manifest.get("id")
            or manifest_obj.get("id")
            or ""
        ).strip()
        if not manifest_chain:
            return {
                "ok": False,
                "error": "upstream_manifest_chain_id_missing",
                "expected_chain_id": expected,
                "upstream": _redact_upstream_url(url),
            }
        if manifest_chain != expected:
            return {
                "ok": False,
                "error": "upstream_manifest_chain_id_mismatch",
                "expected_chain_id": expected,
                "chain_id": manifest_chain,
                "upstream": _redact_upstream_url(url),
            }
        expected_hash = str(os.environ.get("WEALL_EXPECTED_UPSTREAM_MANIFEST_HASH") or os.environ.get("WEALL_CHAIN_MANIFEST_HASH") or "").strip()
        manifest_hash = str(
            manifest.get("manifest_hash")
            or manifest_obj.get("manifest_hash")
            or manifest.get("hash")
            or manifest_obj.get("hash")
            or ""
        ).strip()
        if expected_hash and not manifest_hash:
            return {
                "ok": False,
                "error": "upstream_manifest_hash_missing",
                "expected_manifest_hash": expected_hash,
                "upstream": _redact_upstream_url(url),
            }
        if expected_hash and manifest_hash != expected_hash:
            return {
                "ok": False,
                "error": "upstream_manifest_hash_mismatch",
                "expected_manifest_hash": expected_hash,
                "manifest_hash": manifest_hash,
                "upstream": _redact_upstream_url(url),
            }
        manifest_result = {"checked": True, "manifest_hash": manifest_hash, "chain_id": manifest_chain}
    return {"ok": True, "upstream": _redact_upstream_url(url), "identity": {"chain_id": observed_chain}, "manifest": manifest_result}


def _trusted_anchor_from_upstream(url: str, *, expected_chain_id: str, timeout_s: int) -> Json:
    """Fetch a trusted state-sync anchor from an upstream identity route."""

    try:
        identity = _upstream_get_json(url, "/v1/chain/identity", timeout_s=timeout_s)
    except Exception as exc:
        return {"ok": False, "error": "upstream_anchor_unreachable", "detail": str(exc)[:256], "upstream": _redact_upstream_url(url)}

    observed_chain = str(identity.get("chain_id") or "").strip()
    expected = str(expected_chain_id or "").strip()
    if expected and observed_chain != expected:
        return {
            "ok": False,
            "error": "upstream_anchor_chain_id_mismatch",
            "expected_chain_id": expected,
            "chain_id": observed_chain,
            "upstream": _redact_upstream_url(url),
        }

    anchor = identity.get("snapshot_anchor") or identity.get("trusted_anchor")
    if not isinstance(anchor, dict) or not anchor:
        return {"ok": False, "error": "upstream_trusted_anchor_missing", "upstream": _redact_upstream_url(url)}
    return {"ok": True, "trusted_anchor": dict(anchor), "upstream": _redact_upstream_url(url)}


def _status_from_upstream(url: str, tx_id: str, *, timeout_s: int) -> Json:
    target = f"{str(url).rstrip('/')}/v1/tx/status/{urllib.parse.quote(str(tx_id), safe=':')}"
    headers = {"Accept": "application/json", "X-WeAll-Observer-Forwarded": "1"}
    headers.update(_upstream_operator_headers())
    req = urllib.request.Request(target, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=int(timeout_s)) as resp:  # noqa: S310 - operator-configured upstream
            raw = resp.read(1024 * 1024)
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(parsed, dict):
                return {"ok": False, "error": "bad_upstream_status_shape", "upstream": _redact_upstream_url(url)}
            upstream_tx_id = str(parsed.get("tx_id") or "").strip()
            if upstream_tx_id and upstream_tx_id != str(tx_id):
                return {
                    "ok": False,
                    "error": "upstream_tx_id_mismatch",
                    "tx_id": upstream_tx_id,
                    "expected_tx_id": str(tx_id),
                    "upstream": _redact_upstream_url(url),
                }
            out = dict(parsed)
            out["ok"] = bool(parsed.get("ok"))
            out["upstream"] = _redact_upstream_url(url)
            return out
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:256], "upstream": _redact_upstream_url(url)}


def _drain_tx_outbox(*, request: Request | None = None, only_tx_id: str | None = None, limit: int | None = None) -> Json:
    urls = _normalized_tx_upstream_urls(request)
    with _tx_outbox_lock():
        rows = _load_tx_outbox_unlocked()
        rows = _prune_tx_outbox_rows(rows)
        if not rows:
            _write_tx_outbox_unlocked(rows)
            return {"attempted": False, "accepted": False, "queued": 0, "results": []}
        if not urls:
            _write_tx_outbox_unlocked(rows)
            return {"attempted": False, "accepted": False, "queued": len(rows), "skipped": "no_upstreams_configured", "results": []}
        max_items = int(limit if limit is not None else _env_int_safe("WEALL_TX_OUTBOX_DRAIN_LIMIT", 25, minimum=1, maximum=500))
        selected: list[Json] = []
        for rec in rows:
            tx_id = str(rec.get("tx_id") or "").strip()
            if only_tx_id and tx_id != str(only_tx_id):
                continue
            status = str(rec.get("upstream_status") or "pending")
            if status in {"accepted", "confirmed"} and not only_tx_id:
                continue
            body = rec.get("envelope")
            if not tx_id or not isinstance(body, dict):
                continue
            if len(selected) >= max_items:
                break
            rec["attempts"] = int(rec.get("attempts") or 0) + 1
            rec["last_attempt_ms"] = _now_ms()
            selected.append({"tx_id": tx_id, "body": dict(body), "chain_id": str(rec.get("chain_id") or body.get("chain_id") or "")})
        _write_tx_outbox_unlocked(rows)

    if not selected:
        return {"attempted": False, "accepted": False, "queued": len(_read_tx_outbox()), "results": []}

    timeout_s = _env_int_safe("WEALL_TX_UPSTREAM_TIMEOUT_S", 5, minimum=1, maximum=60)
    results: list[Json] = []
    accepted_any = False
    for item in selected:
        tx_id = str(item.get("tx_id") or "")
        body = item.get("body") if isinstance(item.get("body"), dict) else {}
        per_tx_results = [_forward_tx_to_upstream(url, body, tx_id=tx_id, timeout_s=timeout_s) for url in urls]
        accepted = any(bool(r.get("ok")) for r in per_tx_results if isinstance(r, dict))
        if accepted:
            accepted_any = True
        with _tx_outbox_lock():
            rows = _load_tx_outbox_unlocked()
            rec = _outbox_record_for(rows, tx_id)
            if rec is not None:
                if accepted:
                    rec["upstream_status"] = "accepted"
                    rec["accepted_ms"] = _now_ms()
                    rec["last_error"] = ""
                else:
                    rec["upstream_status"] = "pending"
                    rec["last_error"] = ";".join(str(r.get("error") or "upstream_rejected") for r in per_tx_results if isinstance(r, dict))[:512]
                rec["last_result"] = _compact_tx_outbox_result({"attempted": True, "accepted": bool(accepted), "results": per_tx_results})
                rec["updated_ms"] = _now_ms()
                _write_tx_outbox_unlocked(rows)
        results.append({"tx_id": tx_id, "accepted": bool(accepted), "results": per_tx_results})
    return {"attempted": True, "accepted": bool(accepted_any), "queued": len(_read_tx_outbox()), "results": results}


def _outbox_summary_for_tx(tx_id: str) -> Json | None:
    rec = _outbox_record_for(_read_tx_outbox_best_effort(), tx_id)
    if not isinstance(rec, dict):
        return None
    return {
        "tx_id": str(rec.get("tx_id") or ""),
        "chain_id": str(rec.get("chain_id") or ""),
        "upstream_status": str(rec.get("upstream_status") or "pending"),
        "attempts": int(rec.get("attempts") or 0),
        "created_ms": int(rec.get("created_ms") or 0),
        "updated_ms": int(rec.get("updated_ms") or 0),
        "last_error": str(rec.get("last_error") or ""),
        "confirmed_height": int(rec.get("confirmed_height") or 0),
        "confirmed_block_id": str(rec.get("confirmed_block_id") or ""),
        "local_state_synced": bool(rec.get("local_state_synced", False)),
        "last_result": _compact_tx_outbox_result(rec.get("last_result")),
    }


def _reconcile_outbox_confirmation(tx_id: str) -> Json | None:
    rec = _outbox_record_for(_read_tx_outbox(), tx_id)
    if not isinstance(rec, dict):
        return None
    urls = _normalized_tx_upstream_urls()
    if not urls:
        return _outbox_summary_for_tx(tx_id)
    timeout_s = _env_int_safe("WEALL_TX_UPSTREAM_STATUS_TIMEOUT_S", 3, minimum=1, maximum=30)
    results = [_status_from_upstream(url, tx_id, timeout_s=timeout_s) for url in urls]
    confirmed = next((r for r in results if isinstance(r, dict) and r.get("ok") and str(r.get("status") or "") == "confirmed"), None)
    if isinstance(confirmed, dict):
        _update_tx_outbox_record(
            tx_id,
            {
                "upstream_status": "confirmed",
                "confirmed_ms": _now_ms(),
                "confirmed_height": int(confirmed.get("height") or 0),
                "confirmed_block_id": str(confirmed.get("block_id") or ""),
                "local_state_synced": False,
                "last_result": {"status_reconciliation": results},
                "last_error": "",
            },
        )
        return _outbox_summary_for_tx(tx_id)
    _update_tx_outbox_record(tx_id, {"last_status_probe_ms": _now_ms(), "last_status_probe": results})
    return _outbox_summary_for_tx(tx_id)


def _local_height_for_request(request: Request) -> int:
    ex = _safe_executor(request)
    try:
        st = ex.read_state() if ex is not None and callable(getattr(ex, "read_state", None)) else {}
        return int((st or {}).get("height") or 0)
    except Exception:
        return 0


def _locally_confirmed_tx(request: Request, tx_id: str) -> Json | None:
    idx = _tx_index_lookup(request, tx_id)
    if isinstance(idx, dict):
        return idx
    blk = _tx_block_lookup(request, tx_id)
    if isinstance(blk, dict):
        return blk
    return None


def _request_and_apply_state_sync_from_upstream(
    request: Request,
    url: str,
    *,
    tx_id: str,
    target_height: int,
    timeout_s: int,
) -> Json:
    ex = _safe_executor(request)
    if ex is None or not callable(getattr(ex, "apply_state_sync_response", None)):
        return {"ok": False, "error": "state_sync_apply_unavailable", "upstream": _redact_upstream_url(url)}

    expected_chain_id = str(getattr(ex, "chain_id", "") or "").strip()
    identity = _verify_upstream_identity(url, expected_chain_id=expected_chain_id, timeout_s=timeout_s)
    if not bool(identity.get("ok")):
        return {"ok": False, "error": "upstream_identity_failed", "identity": identity, "upstream": _redact_upstream_url(url)}

    local_height = _local_height_for_request(request)
    if target_height and local_height >= int(target_height):
        # We are already at or above the upstream-confirmed height but still did
        # not find the tx locally. Avoid applying unrelated snapshots; surface
        # the honest gap for the operator/frontend.
        return {
            "ok": False,
            "error": "local_height_at_or_above_target_without_tx",
            "local_height": int(local_height),
            "target_height": int(target_height),
            "upstream": _redact_upstream_url(url),
        }

    anchor_result = _trusted_anchor_from_upstream(
        url, expected_chain_id=expected_chain_id, timeout_s=timeout_s
    )
    if not bool(anchor_result.get("ok")):
        return {
            "ok": False,
            "error": "upstream_trusted_anchor_failed",
            "anchor": anchor_result,
            "upstream": _redact_upstream_url(url),
        }
    trusted_anchor = anchor_result.get("trusted_anchor")
    if not isinstance(trusted_anchor, dict) or not trusted_anchor:
        return {
            "ok": False,
            "error": "upstream_trusted_anchor_missing",
            "upstream": _redact_upstream_url(url),
        }

    body: Json = {
        "mode": "delta",
        "from_height": int(local_height),
        "to_height": int(target_height) if target_height else None,
        "selector": {"tx_id": str(tx_id), "trusted_anchor": trusted_anchor},
    }
    try:
        raw = _upstream_post_json(url, "/v1/sync/request", body, timeout_s=timeout_s)
    except Exception as exc:
        return {"ok": False, "error": "state_sync_request_failed", "detail": str(exc)[:256], "upstream": _redact_upstream_url(url)}

    if not bool(raw.get("ok")) or not isinstance(raw.get("response"), dict):
        return {"ok": False, "error": "bad_state_sync_response", "response": raw, "upstream": _redact_upstream_url(url)}

    try:
        from weall.api.routes_public_parts.state import _sync_response_from_json

        resp = _sync_response_from_json(raw.get("response"))
        metas = ex.apply_state_sync_response(resp, trusted_anchor=trusted_anchor, allow_snapshot_bootstrap=False)
    except Exception as exc:  # noqa: BLE001 - operator reconciliation diagnostic
        return {"ok": False, "error": "state_sync_apply_failed", "detail": str(exc)[:256], "upstream": _redact_upstream_url(url)}

    local = _locally_confirmed_tx(request, tx_id)
    if isinstance(local, dict):
        _update_tx_outbox_record(
            tx_id,
            {
                "upstream_status": "confirmed",
                "local_state_synced": True,
                "confirmed_height": int(local.get("height") or target_height or 0),
                "confirmed_block_id": str(local.get("block_id") or ""),
                "last_error": "",
                "last_local_sync_ms": _now_ms(),
            },
        )
        return {
            "ok": True,
            "upstream": _redact_upstream_url(url),
            "applied_count": len(metas or []),
            "local_state_synced": True,
            "local_confirmation": local,
        }

    return {
        "ok": False,
        "error": "state_sync_applied_but_tx_not_local",
        "upstream": _redact_upstream_url(url),
        "applied_count": len(metas or []),
    }


def _reconcile_and_sync_local_state(request: Request, tx_id: str) -> Json:
    t = str(tx_id or "").strip()
    if not t:
        raise ApiError.bad_request("bad_request", "missing tx_id", {})

    outbound_existing = _outbox_summary_for_tx(t)
    local = _locally_confirmed_tx(request, t)

    if not isinstance(outbound_existing, dict):
        if isinstance(local, dict):
            return {"ok": True, "tx_id": t, "local_state_synced": True, "source": "local", "local_confirmation": local}
        return {"ok": False, "tx_id": t, "error": "tx_not_in_observer_outbox"}

    # observer_local_confirmed_not_upstream_synced: an observer may optimistically
    # apply an outbound tx locally before genesis confirms it. Never convert a
    # local tx-index hit into upstream confirmation; first prove upstream
    # confirmation, then apply/verify trusted state sync.
    outbound = _reconcile_outbox_confirmation(t)
    if not isinstance(outbound, dict):
        outbound = outbound_existing
    if str(outbound.get("upstream_status") or "") != "confirmed":
        return {
            "ok": False,
            "tx_id": t,
            "error": "upstream_not_confirmed",
            "local_state_synced": False,
            "local_confirmation": local or {},
            "outbound_propagation": outbound,
        }

    if bool(outbound.get("local_state_synced")):
        return {
            "ok": True,
            "tx_id": t,
            "local_state_synced": True,
            "source": "already_synced",
            "local_confirmation": local or {},
            "outbound_propagation": outbound,
        }

    target_height = int(outbound.get("confirmed_height") or 0)
    urls = _normalized_tx_upstream_urls()
    if not urls:
        return {"ok": False, "tx_id": t, "error": "no_upstreams_configured", "outbound_propagation": outbound}

    timeout_s = _env_int_safe("WEALL_TX_UPSTREAM_SYNC_TIMEOUT_S", 10, minimum=1, maximum=120)
    results: list[Json] = []
    for url in urls:
        result = _request_and_apply_state_sync_from_upstream(
            request, url, tx_id=t, target_height=target_height, timeout_s=timeout_s
        )
        results.append(result)
        if bool(result.get("ok")) and bool(result.get("local_state_synced")):
            synced = _outbox_summary_for_tx(t) or {}
            return {
                "ok": True,
                "tx_id": t,
                "local_state_synced": True,
                "source": "state_sync",
                "result": result,
                "outbound_propagation": synced,
            }

    _update_tx_outbox_record(t, {"last_local_sync_ms": _now_ms(), "last_local_sync_results": results})
    return {
        "ok": False,
        "tx_id": t,
        "error": "local_state_sync_failed",
        "local_state_synced": False,
        "results": results,
        "outbound_propagation": _outbox_summary_for_tx(t) or outbound,
    }



def _tx_outbox_autodrain_enabled() -> bool:
    return bool(_observer_edge_mode() and _env_bool("WEALL_TX_OUTBOX_AUTODRAIN", False))


def _tx_outbox_autodrain_interval_s() -> float:
    raw = os.environ.get("WEALL_TX_OUTBOX_DRAIN_INTERVAL_S")
    try:
        value = float(str(raw).strip()) if raw is not None and str(raw).strip() else 2.0
    except Exception:
        value = 2.0
    return max(0.25, min(60.0, value))


def _tx_outbox_autodrain_batch() -> int:
    return _env_int_safe("WEALL_TX_OUTBOX_DRAIN_BATCH", 25, minimum=1, maximum=500)


def start_observer_outbox_autodrain() -> threading.Thread | None:
    """Start the observer-edge durable outbox worker when explicitly enabled.

    This worker is deliberately opt-in and only runs for observer-edge posture.
    It never grants authority, produces blocks, or signs validator artifacts; it
    only retries already-admitted, client-signed tx envelopes from the local
    durable outbox to configured upstreams.
    """

    global _OUTBOX_AUTODRAIN_STOP, _OUTBOX_AUTODRAIN_THREAD
    if not _tx_outbox_autodrain_enabled():
        return None
    with _OUTBOX_AUTODRAIN_LOCK:
        if _OUTBOX_AUTODRAIN_THREAD is not None and _OUTBOX_AUTODRAIN_THREAD.is_alive():
            return _OUTBOX_AUTODRAIN_THREAD
        stop = threading.Event()
        _OUTBOX_AUTODRAIN_STOP = stop

        def _worker() -> None:
            # Make one best-effort pass immediately so short-lived operator
            # sessions/tests do not wait for the first interval.
            while not stop.is_set():
                try:
                    _drain_tx_outbox(limit=_tx_outbox_autodrain_batch())
                except Exception:
                    pass
                stop.wait(_tx_outbox_autodrain_interval_s())

        thread = threading.Thread(
            target=_worker,
            name="weall-observer-tx-outbox-drain",
            daemon=True,
        )
        _OUTBOX_AUTODRAIN_THREAD = thread
        thread.start()
        return thread


def stop_observer_outbox_autodrain(_thread: threading.Thread | None = None) -> None:
    global _OUTBOX_AUTODRAIN_STOP, _OUTBOX_AUTODRAIN_THREAD
    with _OUTBOX_AUTODRAIN_LOCK:
        stop = _OUTBOX_AUTODRAIN_STOP
        thread = _OUTBOX_AUTODRAIN_THREAD
        if stop is not None:
            stop.set()
    if thread is not None and thread.is_alive():
        thread.join(timeout=2.0)
    with _OUTBOX_AUTODRAIN_LOCK:
        if _OUTBOX_AUTODRAIN_THREAD is thread:
            _OUTBOX_AUTODRAIN_THREAD = None
            _OUTBOX_AUTODRAIN_STOP = None


def _validate_public_tx_chain_id(*, body: Json, expected_chain_id: str) -> None:
    expected = str(expected_chain_id or "").strip()
    actual = body.get("chain_id")
    actual2 = str(actual).strip() if isinstance(actual, str) else ""

    if strict_tx_sig_domain_enabled() and not actual2:
        raise ApiError.forbidden(
            "missing_chain_id",
            "chain_id is required for public tx submission",
            {"expected_chain_id": expected},
        )

    if actual2 and expected and actual2 != expected:
        raise ApiError.forbidden(
            "chain_id_mismatch",
            "tx chain_id does not match this node",
            {"expected_chain_id": expected, "chain_id": actual2},
        )


def _tx_index_lookup(request: Request, tx_id: str) -> Json | None:
    """Return tx_index row if present."""
    mp = _safe_mempool(request)
    db = getattr(mp, "db", None)
    if db is None:
        return None
    t = str(tx_id or "").strip()
    if not t:
        return None
    try:
        with db.connection() as con:
            row = con.execute(
                "SELECT tx_id, height, block_id, tx_type, signer, included_ts_ms FROM tx_index WHERE tx_id=? LIMIT 1;",
                (t,),
            ).fetchone()
            if row is None:
                return None
            return {
                "tx_id": str(row["tx_id"]),
                "height": int(row["height"]),
                "block_id": str(row["block_id"]),
                "tx_type": str(row["tx_type"]),
                "signer": str(row["signer"]),
                "included_ts_ms": int(row["included_ts_ms"]),
            }
    except Exception:
        return None


def _tx_block_lookup(request: Request, tx_id: str, limit_blocks: int = 256) -> Json | None:
    """
    Fallback lookup for confirmed txs by scanning persisted blocks.

    Why this exists:
      - The status endpoint should not return "unknown" for a tx that is already
        committed in a block, even if tx_index rows are missing or delayed.
      - This keeps user-facing tx status usable while tx_index persistence is
        being hardened in the executor path.
    """
    mp = _safe_mempool(request)
    db = getattr(mp, "db", None)
    ex = _safe_executor(request)
    if db is None:
        return None

    want = str(tx_id or "").strip()
    if not want:
        return None

    chain_id = str(getattr(ex, "chain_id", "") or "").strip() or None

    try:
        with db.connection() as con:
            rows = con.execute(
                """
                SELECT height, block_id, block_json, created_ts_ms
                FROM blocks
                ORDER BY height DESC
                LIMIT ?;
                """,
                (int(limit_blocks),),
            ).fetchall()
    except Exception:
        return None

    for row in rows:
        try:
            height = int(row["height"])
            block_id = str(row["block_id"] or "")
            created_ts_ms = int(row["created_ts_ms"] or 0)
            block_json_raw = row["block_json"]
            block = (
                json.loads(block_json_raw) if isinstance(block_json_raw, str) else block_json_raw
            )
            if not isinstance(block, dict):
                continue

            header = block.get("header")
            header = header if isinstance(header, dict) else {}
            included_ts_ms = int(
                header.get("block_ts_ms") or block.get("block_ts_ms") or created_ts_ms or 0
            )

            # Preferred path: receipts contain tx_id.
            receipts = block.get("receipts")
            if isinstance(receipts, list):
                for receipt in receipts:
                    if not isinstance(receipt, dict):
                        continue
                    r_tx_id = str(receipt.get("tx_id") or "").strip()
                    if r_tx_id == want:
                        return {
                            "tx_id": want,
                            "height": height,
                            "block_id": block_id,
                            "tx_type": str(receipt.get("tx_type") or ""),
                            "signer": str(receipt.get("signer") or ""),
                            "included_ts_ms": included_ts_ms,
                        }

            # Header tx_ids are consensus-visible committed tx IDs. Some
            # controlled-devnet paths can momentarily expose committed state
            # before receipt/tx_index fallback lookup catches up; checking the
            # block header preserves chain authority without trusting mempool
            # residency or observer-local state.
            header_tx_ids = header.get("tx_ids")
            if isinstance(header_tx_ids, list):
                committed_ids = [str(item or "").strip() for item in header_tx_ids]
                if want in committed_ids:
                    tx_type = ""
                    signer = ""
                    txs_for_header = block.get("txs")
                    if isinstance(txs_for_header, list):
                        try:
                            idx = committed_ids.index(want)
                            env_for_header = txs_for_header[idx] if idx < len(txs_for_header) else {}
                            if isinstance(env_for_header, dict):
                                tx_type = str(env_for_header.get("tx_type") or "")
                                signer = str(env_for_header.get("signer") or "")
                        except Exception:
                            tx_type = ""
                            signer = ""
                    return {
                        "tx_id": want,
                        "height": height,
                        "block_id": block_id,
                        "tx_type": tx_type,
                        "signer": signer,
                        "included_ts_ms": included_ts_ms,
                    }

            # Fallback path: compute deterministic tx_id from tx envelopes.
            txs = block.get("txs")
            if isinstance(txs, list):
                for env in txs:
                    if not isinstance(env, dict):
                        continue
                    try:
                        have = compute_tx_id(env, chain_id=chain_id)
                    except Exception:
                        continue
                    if str(have or "").strip() != want:
                        continue
                    return {
                        "tx_id": want,
                        "height": height,
                        "block_id": block_id,
                        "tx_type": str(env.get("tx_type") or ""),
                        "signer": str(env.get("signer") or ""),
                        "included_ts_ms": included_ts_ms,
                    }
        except Exception:
            continue

    return None


def _http_requires_sig_by_default() -> bool:
    """Default HTTP policy: require cryptographic signatures in prod.

    In production, validator-facing/public HTTP must fail closed regardless of
    WEALL_SIGVERIFY overrides. Outside production, operators may opt in.
    """
    mode = _mode()
    override = os.environ.get("WEALL_SIGVERIFY")
    if mode == "prod":
        return True
    if override is None:
        return False
    return bool(str(override).strip() == "1")


@router.post("/tx/submit")
async def tx_submit(request: Request) -> Json:
    """Submit a user tx envelope.

    Goals:
      - idempotent submission (same tx_id + identical envelope => already_known)
      - fail-closed against SYSTEM / receipts over public HTTP
      - suitable for webfront failover across nodes

    Returns:
      { ok, tx_id, status: accepted|already_known, mempool_size }
    """
    ex = _executor(request)
    mp = _mempool(request)

    body = await _read_json_limited(
        request, max_bytes_env="WEALL_MAX_HTTP_TX_BYTES", default_max_bytes=256 * 1024
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "Body must be a tx envelope object", {})

    # Strict schema validation (envelope + known payloads). This is our main
    # backend/frontend contract guardrail.
    try:
        validate_tx_envelope(body)
    except ValidationError as ve:
        raise ApiError.bad_request(
            "invalid_tx",
            "tx envelope failed schema validation",
            {"errors": ve.errors()},
        )

    tx_type = str(body.get("tx_type") or "").strip()
    signer = str(body.get("signer") or "").strip()
    # Keep an immutable copy of the client-signed envelope for observer-edge
    # propagation. Local admission may annotate the dict with tx_id/timestamps.
    forward_body = json.loads(json.dumps(body, sort_keys=True))
    _validate_public_tx_chain_id(
        body=body, expected_chain_id=str(getattr(ex, "chain_id", "") or "")
    )

    # Hard fail-closed: receipts are block/system-only, and must not come from public HTTP.
    if signer == "SYSTEM" or bool(body.get("system", False)):
        raise ApiError.forbidden(
            "system_tx_forbidden",
            "system-only txs cannot be submitted through the public tx endpoint",
            {"tx_type": tx_type, "signer": signer},
        )
    if (
        tx_type.endswith("_RECEIPT")
        or bool(body.get("receipt_only", False))
        or isinstance(body.get("receipt"), dict)
        or isinstance(body.get("receipts"), list)
    ):
        raise ApiError.forbidden(
            "receipt_submission_forbidden",
            "block receipts cannot be submitted through the public tx endpoint",
            {"tx_type": tx_type, "signer": signer},
        )

    # Enforce signer registration / gating for user tx.
    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    _require_registered_signer_for_user_tx(ledger=ledger, tx_type=tx_type, signer=signer)

    # Signature enforcement at the HTTP boundary.
    if _http_requires_sig_by_default():
        if not isinstance(body.get("sig"), str) or not str(body.get("sig") or "").strip():
            raise ApiError.forbidden(
                "missing_sig",
                "signature is required for public tx submission",
                {"tx_type": tx_type, "signer": signer},
            )

        # Full cryptographic verification.
        if not verify_tx_signature(st, body):
            raise ApiError.forbidden(
                "bad_sig",
                "signature verification failed",
                {"tx_type": tx_type, "signer": signer},
            )

    # Compute deterministic id for idempotency (chain_id-aware).
    tx_id = compute_tx_id(body, chain_id=str(getattr(ex, "chain_id", "") or "").strip() or None)

    # Public observer mode must not create a local-only mempool trap. If no
    # verified public upstream can be derived from explicit config or the seed
    # registry, fail before local admission mutates the observer mempool.
    if (
        _observer_edge_mode()
        and public_testnet_enabled()
        and str(request.headers.get("x-weall-observer-forwarded") or "").strip() != "1"
        and not _normalized_tx_upstream_urls(request)
    ):
        upstream = {
            "attempted": False,
            "accepted": False,
            "queued": 0,
            "skipped": "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM",
            "error": "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM",
            "results": [],
        }
        raise ApiError.bad_gateway(
            "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM",
            "public observer has no verified tx upstream for required propagation",
            {"tx_id": tx_id, "upstream_propagation": upstream},
        )

    already = False
    try:
        already = bool(getattr(mp, "contains", lambda _t: False)(tx_id))
    except Exception:
        already = False

    # submit
    if hasattr(ex, "submit_tx"):
        meta = ex.submit_tx(body, ingress="http")
    else:
        meta = mp.add(body)

    if not isinstance(meta, dict) or not meta.get("ok"):
        raise ApiError.forbidden(
            str(meta.get("error") if isinstance(meta, dict) else "submit_failed"),
            "tx rejected",
            {"details": meta if isinstance(meta, dict) else {"meta": str(meta)}},
        )

    out_tx_id = str(meta.get("tx_id") or tx_id).strip() or tx_id
    mp_size = int(getattr(mp, "size", lambda: 0)() if mp is not None else 0)

    # Public /tx/submit must not become a local-only trap during multi-node devnet.
    # Mirror /mempool/submit gossip behavior after successful local admission.
    gossip_attempted = False
    gossip_ok = False
    try:
        nn = _net_node(request)
        if nn is not None and out_tx_id:
            gossip_attempted = True
            msg = nn.build_tx_envelope_msg(body, client_tx_id=out_tx_id)
            nn.gossip_announce_tx(msg)
            gossip_ok = True
    except Exception:
        gossip_ok = False

    if _observer_edge_mode() and str(request.headers.get("x-weall-observer-forwarded") or "").strip() != "1":
        urls = _normalized_tx_upstream_urls(request)
        if (public_testnet_enabled() or _tx_upstream_required()) and not urls:
            upstream = {
                "attempted": False,
                "accepted": False,
                "queued": 0,
                "skipped": "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM" if public_testnet_enabled() else "no_upstreams_configured",
                "error": "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM" if public_testnet_enabled() else "no_upstreams_configured",
                "results": [],
            }
            raise ApiError.bad_gateway(
                "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM" if public_testnet_enabled() else "tx_upstream_propagation_failed",
                "public observer has no verified tx upstream for required propagation" if public_testnet_enabled() else "local observer has no configured upstream for required propagation",
                {"tx_id": out_tx_id, "upstream_propagation": upstream},
            )
        _enqueue_tx_outbox(forward_body, tx_id=out_tx_id, chain_id=str(getattr(ex, "chain_id", "") or ""), request=request)
        if _env_bool("WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT", False):
            upstream = _drain_tx_outbox(request=request, only_tx_id=out_tx_id, limit=1)
        else:
            upstream = {
                "attempted": False,
                "accepted": False,
                "queued": len(_read_tx_outbox()),
                "status": "queued",
                "mode": "durable_outbox",
                "results": [],
            }
    else:
        upstream = _propagate_tx_to_configured_upstreams(request, forward_body, tx_id=out_tx_id)

    return {
        "ok": True,
        "tx_id": out_tx_id,
        "status": "already_known" if (already or bool(meta.get("already_known"))) else "accepted",
        "mempool_size": mp_size,
        "gossip_propagation": {"attempted": gossip_attempted, "accepted": gossip_ok},
        "upstream_propagation": upstream,
    }


@router.get("/observer/edge/status")
def observer_edge_status(request: Request) -> Json:
    _require_observer_edge_operator(request)
    urls = _normalized_tx_upstream_urls(request)
    outbox_rows = _read_tx_outbox()
    return {
        "ok": True,
        "observer_edge_mode": bool(_observer_edge_mode()),
        "upstream_required": bool(_tx_upstream_required()),
        "upstream_count": len(urls),
        "upstreams": [_redact_upstream_url(u) for u in urls],
        "autodrain": {
            "enabled": _tx_outbox_autodrain_enabled(),
            "interval_s": _tx_outbox_autodrain_interval_s(),
            "batch": _tx_outbox_autodrain_batch(),
        },
        "outbox": {
            "count": len(outbox_rows),
            "counts": _outbox_counts(outbox_rows),
            "max_records": _env_int_safe("WEALL_TX_OUTBOX_MAX_RECORDS", 5000, minimum=1, maximum=50000),
        },
    }


@router.post("/observer/edge/outbox/drain")
def observer_edge_outbox_drain(request: Request) -> Json:
    _require_observer_edge_operator(request)
    result = _drain_tx_outbox(request=request)
    rows = _read_tx_outbox()
    return {"ok": True, "result": result, "outbox": {"count": len(rows), "counts": _outbox_counts(rows)}}


@router.post("/observer/edge/reconcile/{tx_id}")
def observer_edge_reconcile_tx(request: Request, tx_id: str) -> Json:
    """Reconcile an upstream-confirmed observer tx into local observer state.

    This operator-controlled endpoint is the explicit bridge between
    "upstream confirmed" and "local observer state has applied the confirming
    block/state delta".  It does not mark ``local_state_synced`` true until the
    tx is found in the local tx index or committed block scan.
    """
    _require_observer_edge_operator(request)
    return _reconcile_and_sync_local_state(request, tx_id)


@router.get("/tx/status/{tx_id}")
def tx_status(request: Request, tx_id: str) -> Json:
    """Return tx status.

    Status values:
      - confirmed: tx included in a persisted block
      - pending: tx present in mempool
      - unknown: not known (or expired and not indexed)

    Returns:
      { ok, tx_id, status, height?, block_id?, included_ts_ms? }
    """
    t = str(tx_id or "").strip()
    if not t:
        raise ApiError.bad_request("bad_request", "missing tx_id", {})

    outbound = _outbox_summary_for_tx(t)

    idx = _tx_index_lookup(request, t)
    if isinstance(idx, dict):
        if outbound:
            reconciled = _reconcile_outbox_confirmation(t)
            if isinstance(reconciled, dict):
                outbound = reconciled
            local_synced = bool(isinstance(outbound, dict) and outbound.get("local_state_synced") is True)
            upstream_confirmed = bool(
                isinstance(outbound, dict)
                and str(outbound.get("upstream_status") or "") == "confirmed"
            )
            return {
                "ok": True,
                "tx_id": t,
                "status": "confirmed" if upstream_confirmed else "local_confirmed",
                "source": "upstream_synced" if local_synced else "observer_local_confirmed_not_upstream_synced",
                "height": int(idx.get("height") or 0),
                "block_id": str(idx.get("block_id") or ""),
                "included_ts_ms": int(idx.get("included_ts_ms") or 0),
                "local_state_synced": local_synced,
                "tx_type": str(idx.get("tx_type") or ""),
                "signer": str(idx.get("signer") or ""),
                "outbound_propagation": outbound or {},
            }
        return {
            "ok": True,
            "tx_id": t,
            "status": "confirmed",
            "height": int(idx.get("height") or 0),
            "block_id": str(idx.get("block_id") or ""),
            "included_ts_ms": int(idx.get("included_ts_ms") or 0),
            "local_state_synced": True,
            "tx_type": str(idx.get("tx_type") or ""),
            "signer": str(idx.get("signer") or ""),
            "outbound_propagation": {},
        }

    # Confirmed chain state is authoritative over stale mempool residency; observer reconciliation can prove upstream confirmation.
    # A tx may remain visible in mempool after block production in controlled
    # devnet paths; status must still report the committed block so observer
    # reconciliation can prove upstream confirmation before local sync.
    blk = _tx_block_lookup(request, t)
    if isinstance(blk, dict):
        return {
            "ok": True,
            "tx_id": t,
            "status": "confirmed",
            "height": int(blk.get("height") or 0),
            "block_id": str(blk.get("block_id") or ""),
            "included_ts_ms": int(blk.get("included_ts_ms") or 0),
            "local_state_synced": True,
            "tx_type": str(blk.get("tx_type") or ""),
            "signer": str(blk.get("signer") or ""),
            "outbound_propagation": outbound or {},
        }

    mp = _safe_mempool(request)
    try:
        if bool(getattr(mp, "contains", lambda _t: False)(t)):
            reconciled = _reconcile_outbox_confirmation(t) if outbound else None
            if isinstance(reconciled, dict) and str(reconciled.get("upstream_status") or "") == "confirmed":
                return {
                    "ok": True,
                    "tx_id": t,
                    "status": "confirmed",
                    "source": "upstream_reconciled",
                    "height": int(reconciled.get("confirmed_height") or 0),
                    "block_id": str(reconciled.get("confirmed_block_id") or ""),
                    "local_state_synced": False,
                    "outbound_propagation": reconciled,
                }
            return {"ok": True, "tx_id": t, "status": "pending", "outbound_propagation": reconciled or outbound or {}}
    except Exception:
        pass

    reconciled = _reconcile_outbox_confirmation(t) if outbound else None
    if isinstance(reconciled, dict) and str(reconciled.get("upstream_status") or "") == "confirmed":
        return {
            "ok": True,
            "tx_id": t,
            "status": "confirmed",
            "source": "upstream_reconciled",
            "height": int(reconciled.get("confirmed_height") or 0),
            "block_id": str(reconciled.get("confirmed_block_id") or ""),
            "local_state_synced": False,
            "outbound_propagation": reconciled,
        }

    return {"ok": True, "tx_id": t, "status": "unknown", "outbound_propagation": reconciled or outbound or {}}


_TX_INDEX_JSON_PATH = Path(__file__).resolve().parents[4] / "generated" / "tx_index.json"


def _load_tx_catalog_rows() -> list[Json]:
    try:
        raw = json.loads(_TX_INDEX_JSON_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

    tx_types = raw.get("tx_types")
    if not isinstance(tx_types, list):
        return []

    rows: list[Json] = []
    for item in tx_types:
        if not isinstance(item, dict):
            continue
        gates = item.get("gates") if isinstance(item.get("gates"), dict) else {}
        tx_name = str(item.get("name") or item.get("tx_type") or "").strip()
        tx_origin = str(item.get("origin") or "").strip()
        tx_context = str(item.get("context") or "").strip()
        rows.append(
            {
                "id": str(item.get("id") or tx_name).strip(),
                "name": tx_name,
                "origin": tx_origin,
                "context": tx_context,
                "domain": str(item.get("domain") or "").strip(),
                "receipt_only": bool(item.get("receipt_only", False)),
                "subject_gate": str(item.get("subject_gate") or gates.get("subject_gate") or "").strip(),
                "api_entrypoints": _tx_public_entrypoints(tx_name, tx_origin, tx_context),
                "gates": gates,
            }
        )
    rows.sort(key=lambda row: (str(row.get("domain") or ""), str(row.get("name") or "")))
    return rows


def _count_by(rows: list[Json], key: str) -> list[Json]:
    counts: dict[str, int] = {}
    for row in rows:
        label = str(row.get(key) or "").strip() or "Unknown"
        counts[label] = int(counts.get(label, 0)) + 1
    return [
        {"name": name, "count": int(count)}
        for name, count in sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0]).lower()))
    ]


@router.get("/tx/catalog")
def tx_catalog(context: str | None = None, domain: str | None = None, search: str | None = None) -> Json:
    rows = _load_tx_catalog_rows()

    want_context = str(context or "").strip().lower()
    want_domain = str(domain or "").strip().lower()
    want_search = str(search or "").strip().lower()

    filtered: list[Json] = []
    for row in rows:
        row_context = str(row.get("context") or "").strip().lower()
        row_domain = str(row.get("domain") or "").strip().lower()
        row_name = str(row.get("name") or "").strip().lower()
        row_gate = str(row.get("subject_gate") or "").strip().lower()

        if want_context and row_context != want_context:
            continue
        if want_domain and row_domain != want_domain:
            continue
        if want_search and want_search not in row_name and want_search not in row_gate and want_search not in row_domain:
            continue
        filtered.append(row)

    return {
        "ok": True,
        "total": int(len(rows)),
        "count": int(len(filtered)),
        "filters": {
            "context": str(context or "").strip(),
            "domain": str(domain or "").strip(),
            "search": str(search or "").strip(),
        },
        "summary": {
            "by_context": _count_by(filtered, "context"),
            "by_domain": _count_by(filtered, "domain"),
        },
        "items": filtered,
    }
