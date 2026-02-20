# projects/Weall-Protocol/src/weall/api/routes_public_parts/media.py
from __future__ import annotations

import os
import re
import mimetypes
from typing import Any, Dict, Tuple, Set

from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import RedirectResponse

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _executor, _mempool, _snapshot
from weall.api.security import require_account_session
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.ledger.state import LedgerView
from weall.util.ipfs_cid import validate_ipfs_cid


router = APIRouter()


def _env_int(name: str, default: int) -> int:
    try:
        v = os.getenv(name)
        if v is None:
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _sanitize_filename(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "upload"
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", name)
    return name[:128] or "upload"


def _require_tier3(st: Dict[str, Any], account: str) -> None:
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
    if tier < 3:
        raise ApiError.forbidden("forbidden", "Media upload requires PoH tier 3+")


def _next_account_nonce(st: Dict[str, Any], account: str) -> int:
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


def _storage_get(st: Dict[str, Any]) -> Dict[str, Any]:
    storage = st.get("storage")
    return storage if isinstance(storage, dict) else {}


def _pin_info_for_cid_unique_ops(st: Dict[str, Any], cid: str) -> Tuple[bool, int, int, int, int, int]:
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
    ok_ops: Set[str] = set()

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


def _replication_factor(st: Dict[str, Any]) -> int:
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


@router.post("/v1/media/upload")
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
    viewer = require_account_session(request, st)
    _require_tier3(st, viewer)

    max_bytes = _env_int("WEALL_IPFS_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)

    name = _sanitize_filename(file.filename or "upload")
    mime = (file.content_type or "").strip() or (mimetypes.guess_type(name)[0] or "application/octet-stream")

    size = _file_size(file)
    if size == 0:
        raise ApiError.invalid("invalid_payload", "empty_file")
    if size > 0 and size > max_bytes:
        raise ApiError.invalid("invalid_payload", f"file_too_large (max {max_bytes} bytes)")

    try:
        file.file.seek(0)
    except Exception:
        pass

    pin_on_upload = _env_bool("WEALL_IPFS_PIN_ON_UPLOAD", False)

    try:
        cid, ipfs_reported_size = ipfs_add_fileobj(name=name, fileobj=file.file, pin=bool(pin_on_upload))
    except RuntimeError as e:
        raise ApiError.bad_request("ipfs_error", str(e))

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.bad_request("ipfs_error", f"invalid_cid_from_ipfs:{v.reason}")

    final_size = size if size >= 0 else int(ipfs_reported_size)

    auto_pin_request = _env_bool("WEALL_MEDIA_AUTO_PIN_REQUEST", False)
    pin_request: Dict[str, Any] = {"submitted": False, "tx_id": None, "error": None, "envelope": None}

    suggested_env = {
        "tx_type": "IPFS_PIN_REQUEST",
        "signer": viewer,
        "nonce": _next_account_nonce(st, viewer),
        "payload": {"cid": cid, "size_bytes": int(final_size) if int(final_size) > 0 else 0},
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
                pin_request["error"] = {"code": res.code, "reason": res.reason, "details": res.details}
            else:
                pin_request["submitted"] = True
                pin_request["tx_id"] = res.tx_id
        except Exception as e:
            pin_request["error"] = {"code": "pin_request_submit_failed", "reason": str(e), "details": {}}

    return {
        "ok": True,
        "cid": cid,
        "name": name,
        "mime": mime,
        "size": int(final_size),
        "uri": f"ipfs://{cid}",
        "gateway_url": ipfs_gateway_url(cid),
        "pinned_on_upload": bool(pin_on_upload),
        "pin_request": pin_request,
    }


@router.get("/v1/media/gateway/{cid}")
async def v1_media_gateway(cid: str):
    """Redirect to the configured public gateway for a CID."""
    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)
    return RedirectResponse(ipfs_gateway_url(cid))


@router.get("/v1/media/status/{cid}")
async def v1_media_status(request: Request, cid: str):
    """Return durability status based on operator confirmations."""
    st = _snapshot(request)

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)

    rf = _replication_factor(st)
    pin_requested, ok_unique_ops, ok_total, fail_total, last_nonce, last_height = _pin_info_for_cid_unique_ops(st, v.cid)

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
