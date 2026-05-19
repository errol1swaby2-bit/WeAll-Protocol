# projects/Weall-Protocol/src/weall/api/routes_public_parts/media.py
from __future__ import annotations

import hashlib
import mimetypes
import os
from pathlib import Path
import re
import threading
import urllib.error
import urllib.request
from typing import Any

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse

from weall.api.errors import ApiError
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.api.routes_public_parts.common import _executor, _mempool, _snapshot, _str_param
from weall.api.security import require_account_session
from weall.ledger.state import LedgerView
from weall.storage.ipfs_partition import can_accept_bytes, read_partition_config
from weall.util.ipfs_cid import validate_ipfs_cid

router = APIRouter()


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return bool(default)
    v = str(raw).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    if _mode() == "prod":
        raise ValueError(f"invalid_boolean_env:{name}")
    return bool(default)


_MEDIA_FETCH_SEMAPHORE: threading.BoundedSemaphore | None = None
_MEDIA_FETCH_SEMAPHORE_LIMIT: int | None = None


def _media_fetch_semaphore(limit: int) -> threading.BoundedSemaphore:
    global _MEDIA_FETCH_SEMAPHORE, _MEDIA_FETCH_SEMAPHORE_LIMIT
    safe_limit = max(1, int(limit))
    if _MEDIA_FETCH_SEMAPHORE is None or _MEDIA_FETCH_SEMAPHORE_LIMIT != safe_limit:
        _MEDIA_FETCH_SEMAPHORE = threading.BoundedSemaphore(safe_limit)
        _MEDIA_FETCH_SEMAPHORE_LIMIT = safe_limit
    return _MEDIA_FETCH_SEMAPHORE


def _cache_enabled() -> bool:
    return _env_bool("WEALL_MEDIA_PROXY_CACHE_ENABLED", True)


def _fetch_enabled() -> bool:
    return _env_bool("WEALL_MEDIA_PROXY_FETCH_ENABLED", True)


def _media_cache_dir() -> Path:
    configured = str(os.environ.get("WEALL_MEDIA_CACHE_DIR") or "").strip()
    root = configured or ".weall-media-cache"
    return Path(root).expanduser().resolve()


def _cache_path_for_cid(cid: str) -> Path:
    digest = hashlib.sha256(cid.encode("utf-8")).hexdigest()
    return _media_cache_dir() / digest[:2] / f"{digest}.bin"


def _media_provider_url(cid: str) -> str:
    # Reuse the configured gateway as the first production provider. Future
    # provider discovery can add genesis/peer/storage-helper URLs here without
    # changing the frontend contract.
    return ipfs_gateway_url(cid)


def _copy_provider_to_cache(*, cid: str, dest: Path, max_bytes: int, timeout_s: int) -> tuple[int, str]:
    url = _media_provider_url(cid)
    tmp = dest.with_suffix(".tmp")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if tmp.exists():
        try:
            tmp.unlink()
        except Exception:
            pass

    req = urllib.request.Request(url, headers={"Accept": "*/*", "User-Agent": "WeAllObserverMediaProxy/1"})
    try:
        with urllib.request.urlopen(req, timeout=max(1, int(timeout_s))) as resp:  # noqa: S310 - configured gateway/provider URL
            content_length = resp.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > max_bytes:
                        raise ApiError.payload_too_large(
                            "media_too_large",
                            "media exceeds local observer fetch budget",
                            {"cid": cid, "bytes": int(content_length), "max_bytes": int(max_bytes)},
                        )
                except ApiError:
                    raise
                except Exception:
                    pass

            total = 0
            with tmp.open("wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ApiError.payload_too_large(
                            "media_too_large",
                            "media exceeds local observer fetch budget",
                            {"cid": cid, "bytes": int(total), "max_bytes": int(max_bytes)},
                        )
                    f.write(chunk)

        tmp.replace(dest)
        return total, url
    except ApiError:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise ApiError.bad_request(
            "media_provider_unavailable",
            "media provider unavailable",
            {"cid": cid, "provider": url, "reason": str(exc)},
        )


def _content_media_index(st: dict[str, Any]) -> dict[str, Any]:
    content = st.get("content")
    if not isinstance(content, dict):
        return {}
    media = content.get("media")
    return media if isinstance(media, dict) else {}


def _media_summary(media_id: str, rec: Any) -> dict[str, Any]:
    obj = rec if isinstance(rec, dict) else {}
    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    cid = str(obj.get("cid") or payload.get("cid") or payload.get("upload_ref") or "").strip()
    return {
        "media_id": media_id,
        "cid": cid,
        "mime": str(payload.get("mime") or payload.get("mime_type") or payload.get("content_type") or "").strip(),
        "name": str(payload.get("name") or payload.get("filename") or media_id).strip(),
        "kind": str(obj.get("kind") or payload.get("kind") or "").strip(),
        "bytes": int(payload.get("size") or payload.get("size_bytes") or 0) if str(payload.get("size") or payload.get("size_bytes") or "0").isdigit() else 0,
        "declared_by": str(obj.get("declared_by") or "").strip(),
        "declared_at_nonce": obj.get("declared_at_nonce"),
        "load_policy": "viewport",
        "fetch_path": f"/v1/media/proxy/{cid}" if cid else "",
    }

def _sanitize_filename(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "upload"
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", name)
    return name[:128] or "upload"


def _require_tier2_live_verified(st: dict[str, Any], account: str) -> None:
    accounts = st.get("accounts")
    if not isinstance(accounts, dict):
        raise ApiError.forbidden("forbidden", "Account state unavailable")
    rec = accounts.get(account)
    if not isinstance(rec, dict):
        raise ApiError.forbidden("forbidden", "Account not registered")
    if bool(rec.get("banned", False)):
        raise ApiError.forbidden("forbidden", "Account is banned")
    if bool(rec.get("locked", False)):
        raise ApiError.forbidden("forbidden", "Account is locked")
    tier = int(rec.get("poh_tier", 0) or 0)
    if tier < 2:
        raise ApiError.forbidden("forbidden", "Media upload requires Tier 2 / Live Verified Human")


def _next_account_nonce(st: dict[str, Any], account: str) -> int:
    accounts = st.get("accounts")
    if isinstance(accounts, dict):
        rec = accounts.get(account)
        if isinstance(rec, dict):
            cur = rec.get("nonce")
            try:
                return int(cur or 0) + 1
            except Exception:
                pass
    return 1


def _file_size(upload: UploadFile) -> int:
    """
    Best-effort size discovery without reading into memory.
    UploadFile.file is typically a SpooledTemporaryFile which supports seek/tell.
    """
    try:
        f = upload.file
        cur = f.tell()
        f.seek(0, 2)  # end
        size = int(f.tell())
        f.seek(cur, 0)
        return size
    except Exception:
        return -1


def _storage_get(st: dict[str, Any]) -> dict[str, Any]:
    storage = st.get("storage")
    return storage if isinstance(storage, dict) else {}


def _pin_info_for_cid_unique_ops(
    st: dict[str, Any], cid: str
) -> tuple[bool, int, int, int, int, int]:
    """
    Returns:
      (pin_requested, ok_unique_ops, ok_total, fail_total, last_nonce, last_height)

    Notes:
      - "ok_unique_ops" counts distinct operator_id values where ok=True.
      - If operator_id missing on confirm, it contributes to ok_total/fail_total,
        but does NOT contribute to ok_unique_ops.
    """
    storage = _storage_get(st)
    pins = storage.get("pins")
    pin_confirms = storage.get("pin_confirms")

    pin_requested = False
    ok_total = 0
    fail_total = 0
    last_nonce = 0
    last_height = 0
    ok_ops: set[str] = set()

    if isinstance(pins, dict):
        for _, rec_any in pins.items():
            if not isinstance(rec_any, dict):
                continue
            if str(rec_any.get("cid") or "").strip() == cid:
                pin_requested = True
                break

    if isinstance(pin_confirms, list):
        for item_any in pin_confirms:
            if not isinstance(item_any, dict):
                continue
            if str(item_any.get("cid") or "").strip() != cid:
                continue

            ok = bool(item_any.get("ok"))
            if ok:
                ok_total += 1
            else:
                fail_total += 1

            op = item_any.get("operator_id")
            if ok and isinstance(op, str) and op.strip():
                ok_ops.add(op.strip())

            try:
                n = int(item_any.get("at_nonce") or 0)
            except Exception:
                n = 0
            try:
                h = int(item_any.get("at_height") or 0)
            except Exception:
                h = 0
            if n > last_nonce:
                last_nonce = n
            if h > last_height:
                last_height = h

    return pin_requested, len(ok_ops), ok_total, fail_total, last_nonce, last_height


def _replication_factor(st: dict[str, Any]) -> int:
    """
    Source-of-truth order:
      1) env WEALL_IPFS_REPLICATION_FACTOR (int)
      2) state params.ipfs_replication_factor (int) if present
      3) default 1
    """
    env_rf = _env_int("WEALL_IPFS_REPLICATION_FACTOR", 0)
    if env_rf > 0:
        return env_rf

    params = st.get("params")
    if isinstance(params, dict):
        try:
            v = int(params.get("ipfs_replication_factor") or 0)
            if v > 0:
                return v
        except Exception:
            pass

    return 1


@router.post("/media/upload")
async def v1_media_upload(request: Request, file: UploadFile = File(...)):
    """Upload a file and store it on IPFS (streamed; no full-RAM read).

    Production posture:
      - Upload returns a CID.
      - Durability should come from operator pin-confirmations, not API-node pinning.
      - By default we DO NOT pin on upload (configurable).

    Returns:
      { ok, cid, name, mime, size, uri, gateway_url, pin_request, pinned_on_upload }
    """
    st = _snapshot(request)
    try:
        viewer = require_account_session(request, st)
    except PermissionError as e:
        code = str(e) or "session_missing"
        raise ApiError.forbidden(code, code.replace("_", " "), {})
    _require_tier2_live_verified(st, viewer)

    max_bytes = _env_int("WEALL_IPFS_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)

    name = _sanitize_filename(file.filename or "upload")
    mime = (file.content_type or "").strip() or (
        mimetypes.guess_type(name)[0] or "application/octet-stream"
    )

    size = _file_size(file)
    if size == 0:
        raise ApiError.invalid("invalid_payload", "empty_file")
    if size > 0 and size > max_bytes:
        raise ApiError.invalid("invalid_payload", f"file_too_large (max {max_bytes} bytes)")

    # Local partition/quota enforcement ("mounted path you control").
    # If WEALL_IPFS_PARTITION_PATH is unset, this check is disabled.
    part_path, part_cap, part_reserve = read_partition_config()
    need_bytes = int(size if size > 0 else max_bytes)
    ok, reason, details = can_accept_bytes(
        partition_path=part_path,
        cap_bytes=int(part_cap),
        reserve_bytes=int(part_reserve),
        need_bytes=int(need_bytes),
    )
    if not ok:
        # Fail closed: if operator configured a partition, do not allow uploads
        # that would exceed local budget.
        raise ApiError.forbidden("insufficient_storage", f"ipfs_partition:{reason}", details)

    try:
        file.file.seek(0)
    except Exception:
        pass

    pin_on_upload = _env_bool("WEALL_IPFS_PIN_ON_UPLOAD", False)

    try:
        cid, ipfs_reported_size = ipfs_add_fileobj(
            name=name, fileobj=file.file, pin=bool(pin_on_upload)
        )
    except RuntimeError as e:
        raise ApiError.bad_request("ipfs_error", str(e))

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.bad_request("ipfs_error", f"invalid_cid_from_ipfs:{v.reason}")

    final_size = size if size >= 0 else int(ipfs_reported_size)

    auto_pin_request = _env_bool("WEALL_MEDIA_AUTO_PIN_REQUEST", False)
    pin_request: dict[str, Any] = {
        "submitted": False,
        "tx_id": None,
        "error": None,
        "envelope": None,
    }

    suggested_env = {
        "tx_type": "IPFS_PIN_REQUEST",
        "signer": viewer,
        "nonce": _next_account_nonce(st, viewer),
        "payload": {"cid": cid, "size_bytes": int(final_size) if int(final_size) > 0 else 0},
        "upload_ref": cid,
        "ref": cid,
        "sig": "",
        "parent": None,
        "system": False,
    }
    pin_request["envelope"] = suggested_env

    if auto_pin_request:
        try:
            ex = _executor(request)
            mp = _mempool(request)

            snap = ex.snapshot()
            ledger = LedgerView.from_ledger(snap)

            res = mp.submit(ledger=ledger, tx=suggested_env, context="mempool")
            if not res.ok:
                pin_request["error"] = {
                    "code": res.code,
                    "reason": res.reason,
                    "details": res.details,
                }
            else:
                pin_request["submitted"] = True
                pin_request["tx_id"] = res.tx_id
        except Exception as e:
            pin_request["error"] = {
                "code": "pin_request_submit_failed",
                "reason": str(e),
                "details": {},
            }

    return {
        "ok": True,
        "cid": cid,
        "upload_ref": cid,
        "ref": cid,
        "name": name,
        "mime": mime,
        "size": int(final_size),
        "uri": f"ipfs://{cid}",
        "gateway_url": ipfs_gateway_url(cid),
        "pinned_on_upload": bool(pin_on_upload),
        "pin_request": pin_request,
    }


@router.get("/media/gateway/{cid}")
async def v1_media_gateway(cid: str):
    """Redirect to the configured public gateway for a CID."""
    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)
    return RedirectResponse(ipfs_gateway_url(cid))


@router.get("/media/status/{cid}")
async def v1_media_status(request: Request, cid: str):
    """Return durability status based on operator confirmations."""
    st = _snapshot(request)

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)

    rf = _replication_factor(st)
    pin_requested, ok_unique_ops, ok_total, fail_total, last_nonce, last_height = (
        _pin_info_for_cid_unique_ops(st, v.cid)
    )

    durable = bool(ok_unique_ops >= rf and rf > 0)

    return {
        "ok": True,
        "cid": v.cid,
        "replication_factor": int(rf),
        "pin_requested": bool(pin_requested),
        "ok_unique_ops": int(ok_unique_ops),
        "ok_total": int(ok_total),
        "fail_total": int(fail_total),
        "durable": bool(durable),
        "last_confirm_nonce": int(last_nonce),
        "last_confirm_height": int(last_height),
    }


@router.get("/media/resolve")
async def v1_media_resolve(request: Request):
    """Resolve committed media ids into metadata only.

    This endpoint is intentionally blob-free. It lets feed/frontends resolve a
    bounded visible page of media ids without reading the full state snapshot or
    causing the observer node to fetch hundreds of media objects.
    """
    st = _snapshot(request)
    raw_ids = _str_param(request.query_params.get("ids")).strip()
    limit = max(1, min(100, _env_int("WEALL_MEDIA_RESOLVE_MAX_IDS", 50)))

    ids: list[str] = []
    for chunk in raw_ids.split(","):
        media_id = chunk.strip()
        if not media_id or media_id in ids:
            continue
        ids.append(media_id)
        if len(ids) >= limit:
            break

    media = _content_media_index(st)
    items: dict[str, Any] = {}
    missing: list[str] = []
    for media_id in ids:
        rec = media.get(media_id)
        if isinstance(rec, dict):
            items[media_id] = _media_summary(media_id, rec)
        else:
            missing.append(media_id)

    return {
        "ok": True,
        "items": items,
        "missing": missing,
        "count": len(items),
        "limit": int(limit),
        "load_policy": "viewport",
    }


@router.get("/media/proxy/{cid}")
def v1_media_proxy(cid: str):
    """Serve media through the local observer with bounded cache/fetch policy.

    Feed/list endpoints never call this. The frontend should request this only
    when a media card enters or approaches the viewport. The observer mediates
    provider fetch, byte budget, concurrency, and local cache.
    """
    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)

    normalized_cid = v.cid
    max_bytes = max(1, _env_int("WEALL_MEDIA_PROXY_MAX_BYTES", 25 * 1024 * 1024))
    timeout_s = max(1, _env_int("WEALL_MEDIA_PROXY_TIMEOUT_S", 20))
    inflight = max(1, _env_int("WEALL_MEDIA_PROXY_MAX_INFLIGHT", 4))

    if not _cache_enabled():
        # Controlled fallback: still avoid feed-triggered bulk loads because only
        # viewport URLs reach this route. Operators can disable local cache and
        # redirect to their configured gateway/provider.
        return RedirectResponse(_media_provider_url(normalized_cid))

    path = _cache_path_for_cid(normalized_cid)
    if path.exists() and path.is_file():
        return FileResponse(
            path,
            media_type="application/octet-stream",
            headers={"X-WeAll-Media-Cache": "hit", "X-WeAll-Media-Load-Policy": "viewport"},
        )

    if not _fetch_enabled():
        raise ApiError.not_found(
            "media_not_cached",
            "media is not cached on this observer",
            {"cid": normalized_cid, "load_policy": "viewport"},
        )

    sem = _media_fetch_semaphore(inflight)
    acquired = sem.acquire(blocking=False)
    if not acquired:
        raise ApiError.too_many(
            "media_fetch_busy",
            "observer media fetch budget is busy",
            {"cid": normalized_cid, "max_inflight": int(inflight)},
        )
    try:
        _copy_provider_to_cache(cid=normalized_cid, dest=path, max_bytes=max_bytes, timeout_s=timeout_s)
    finally:
        sem.release()

    return FileResponse(
        path,
        media_type="application/octet-stream",
        headers={"X-WeAll-Media-Cache": "miss-store", "X-WeAll-Media-Load-Policy": "viewport"},
    )
