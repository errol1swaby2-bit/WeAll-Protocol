from __future__ import annotations

"""Controlled-devnet observer read-through state sync helpers.

This module intentionally does not expose public HTTP routes.  It is used by
read surfaces on local observer rehearsal nodes so a browser does not make
write decisions from a stale observer read model while the upstream Genesis
node has already confirmed newer account/content state.

Production remains fail-closed: the helper is inert unless the node is running
in observer edge mode and WEALL_OBSERVER_READ_THROUGH_SYNC is explicitly set.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any

from fastapi import Request

Json = dict[str, Any]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0, maximum: int = 100_000) -> int:
    try:
        value = int(str(os.environ.get(name, default)).strip())
    except Exception:
        value = default
    return max(minimum, min(maximum, value))


def _observer_edge_mode() -> bool:
    return _env_bool("WEALL_OBSERVER_EDGE_MODE", False) or _env_bool("WEALL_OBSERVER_MODE", False)


def _readthrough_enabled() -> bool:
    return bool(_observer_edge_mode() and _env_bool("WEALL_OBSERVER_READ_THROUGH_SYNC", False))


def _upstream_urls() -> list[str]:
    raw = str(os.environ.get("WEALL_TX_UPSTREAM_URLS") or "").strip()
    urls: list[str] = []
    for part in raw.replace(";", ",").split(","):
        url = part.strip().rstrip("/")
        if url and url not in urls:
            urls.append(url)
    for name in ("WEALL_GENESIS_API_BASE", "WEALL_BOOTSTRAP_API_BASE"):
        url = str(os.environ.get(name) or "").strip().rstrip("/")
        if url and url not in urls:
            urls.append(url)
    return urls[: _env_int("WEALL_OBSERVER_READ_THROUGH_MAX_UPSTREAMS", 2, minimum=1, maximum=8)]


def _headers() -> dict[str, str]:
    out = {"accept": "application/json"}
    token = (
        os.environ.get("WEALL_STATE_SYNC_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OPERATOR_TOKEN")
        or ""
    )
    if token:
        out["x-weall-state-sync-operator-token"] = token
        out["x-weall-observer-operator-token"] = token
        out["x-weall-operator-token"] = token
    return out


def _get_json(url: str, path: str, *, timeout_s: int) -> Json:
    req = urllib.request.Request(url.rstrip("/") + path, method="GET", headers=_headers())
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - operator-configured upstream
        raw = resp.read().decode("utf-8", errors="replace")
    parsed = json.loads(raw) if raw.strip() else {}
    return parsed if isinstance(parsed, dict) else {}


def _post_json(url: str, path: str, body: Json, *, timeout_s: int) -> Json:
    payload = json.dumps(body, sort_keys=True).encode("utf-8")
    headers = _headers()
    headers["content-type"] = "application/json"
    req = urllib.request.Request(url.rstrip("/") + path, data=payload, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - operator-configured upstream
        raw = resp.read().decode("utf-8", errors="replace")
    parsed = json.loads(raw) if raw.strip() else {}
    return parsed if isinstance(parsed, dict) else {}


def _executor(request: Request) -> Any | None:
    try:
        return getattr(request.app.state, "executor", None)
    except Exception:
        return None


def _local_height(request: Request) -> int:
    ex = _executor(request)
    try:
        state = ex.snapshot() if ex is not None else {}
    except Exception:
        state = {}
    if not isinstance(state, dict):
        return 0
    try:
        return max(0, int(state.get("height") or 0))
    except Exception:
        return 0


def sync_observer_from_upstream_if_enabled(request: Request, *, reason: str) -> Json:
    """Best-effort catch-up for controlled-devnet observer read surfaces.

    The helper intentionally swallows failures and returns diagnostics.  Reads
    must remain available even when the upstream is temporarily unreachable;
    callers can include the returned metadata if they want, but they should not
    fail the public read route because of a rehearsal sync miss.
    """

    if not _readthrough_enabled():
        return {"attempted": False, "skipped": "disabled"}

    ex = _executor(request)
    if ex is None or not callable(getattr(ex, "apply_state_sync_response", None)):
        return {"attempted": False, "skipped": "executor_unavailable"}

    local_height = _local_height(request)
    timeout_s = _env_int("WEALL_OBSERVER_READ_THROUGH_SYNC_TIMEOUT_S", 8, minimum=1, maximum=60)
    expected_chain = str(getattr(ex, "chain_id", "") or "").strip()

    results: list[Json] = []
    for url in _upstream_urls():
        try:
            ident = _get_json(url, "/v1/chain/identity", timeout_s=timeout_s)
            upstream_chain = str(ident.get("chain_id") or "").strip()
            if expected_chain and upstream_chain and upstream_chain != expected_chain:
                results.append({"ok": False, "upstream": url, "error": "chain_id_mismatch"})
                continue
            upstream_height = int(ident.get("height") or 0)
            if upstream_height <= local_height:
                results.append({"ok": True, "upstream": url, "skipped": "not_behind", "local_height": local_height, "upstream_height": upstream_height})
                continue
            trusted_anchor = ident.get("snapshot_anchor") or {}
            req = {
                "mode": "delta",
                "from_height": local_height,
                "to_height": upstream_height,
                "selector": {"trusted_anchor": trusted_anchor, "reason": str(reason or "read")[:80]},
            }
            raw = _post_json(url, "/v1/sync/request", req, timeout_s=timeout_s)
            if not bool(raw.get("ok")) or not isinstance(raw.get("response"), dict):
                results.append({"ok": False, "upstream": url, "error": "bad_sync_response", "response_ok": bool(raw.get("ok"))})
                continue
            from weall.api.routes_public_parts.state import _sync_response_from_json

            resp = _sync_response_from_json(raw.get("response"))
            metas = ex.apply_state_sync_response(resp, trusted_anchor=trusted_anchor, allow_snapshot_bootstrap=False)
            after = _local_height(request)
            results.append({"ok": True, "upstream": url, "applied_count": len(metas or []), "before_height": local_height, "after_height": after, "upstream_height": upstream_height})
            if after >= upstream_height:
                return {"attempted": True, "ok": True, "source": "upstream_state_sync", "reason": reason, "results": results}
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            results.append({"ok": False, "upstream": url, "error": type(exc).__name__, "detail": str(exc)[:160]})
        except Exception as exc:  # noqa: BLE001 - diagnostic, best effort only
            results.append({"ok": False, "upstream": url, "error": type(exc).__name__, "detail": str(exc)[:160]})

    return {"attempted": bool(results), "ok": any(bool(r.get("ok")) for r in results), "reason": reason, "results": results}
