# projects/Weall-Protocol/src/weall/api/routes_public_parts/media.py
from __future__ import annotations

import hashlib
import hmac
import json
import ipaddress
import mimetypes
import os
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse

from weall.api.errors import ApiError
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.api.routes_public_parts.common import _executor, _mempool, _snapshot, _str_param
from weall.api.security import require_account_session
from weall.ledger.state import LedgerView
from weall.storage.ipfs_partition import can_accept_bytes, read_partition_config
from weall.util.ipfs_cid import validate_ipfs_cid, verify_cid_multihash_bytes

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


def _request_is_loopback(request: Request) -> bool:
    host = ""
    try:
        host = str(request.client.host or "") if request.client else ""
    except Exception:
        host = ""
    if host.lower() == "localhost":
        return True
    try:
        return bool(ipaddress.ip_address(host).is_loopback)
    except Exception:
        return False


def _media_operator_token() -> str:
    return str(
        os.environ.get("WEALL_OPERATOR_TOKEN")
        or os.environ.get("WEALL_MEDIA_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN")
        or ""
    ).strip()


def _request_has_media_operator_auth(request: Request) -> bool:
    # In production observer mode, loopback callers are not automatically
    # operator-authorized.  Browser apps and unrelated local processes should
    # not learn raw provider topology unless they present an operator token.
    default_local_exempt = _mode() != "prod"
    if _request_is_loopback(request) and not _env_bool("WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL", not default_local_exempt):
        return True
    want = _media_operator_token()
    if not want:
        return False
    got = str(
        request.headers.get("X-WeAll-Operator-Token")
        or request.headers.get("X-WeAll-Media-Operator-Token")
        or request.headers.get("X-WeAll-Observer-Operator-Token")
        or ""
    ).strip()
    return bool(got and hmac.compare_digest(got, want))


def _media_provider_urls_public() -> bool:
    # Provider URLs can reveal LAN topology/storage-helper addresses.  In prod,
    # expose the route as redacted metadata unless the operator explicitly opts
    # into public URLs or authenticates with an operator token.
    return _env_bool("WEALL_MEDIA_PROVIDER_URLS_PUBLIC", _mode() != "prod")


def _provider_kind(url: str) -> str:
    text = str(url or "").lower()
    if "/v1/media/proxy/" in text or text.endswith("/v1/media/proxy"):
        return "weall_media_proxy"
    if "/ipfs/" in text or text.endswith("/ipfs"):
        return "ipfs_gateway"
    if "storage" in text or "pin" in text:
        return "storage_provider"
    return "media_provider"


def _provider_diagnostics(urls: list[str]) -> list[dict[str, Any]]:
    """Return topology-safe provider diagnostics for public error surfaces."""

    out: list[dict[str, Any]] = []
    for url in urls:
        out.append({"kind": _provider_kind(url), "redacted": True})
    return out


def _allow_unverified_media_redirect() -> bool:
    # Redirecting a browser directly to a provider bypasses the observer's byte
    # verification and cache poisoning protections. Keep this fail-closed in
    # production unless an operator explicitly opts into the weaker behavior.
    return _env_bool("WEALL_MEDIA_PROXY_ALLOW_UNVERIFIED_REDIRECT", _mode() != "prod")


def _media_integrity_required() -> bool:
    # Production observer nodes should not cache unverified bytes.  A committed
    # file-byte sha256 is preferred; supported CIDs can also be checked directly
    # through their sha2-256 multihash.
    if "WEALL_MEDIA_PROXY_REQUIRE_INTEGRITY" in os.environ:
        return _env_bool("WEALL_MEDIA_PROXY_REQUIRE_INTEGRITY", True)
    if _env_bool("WEALL_MEDIA_PROXY_REQUIRE_BYTE_HASH", False):
        return True
    if _env_bool("WEALL_MEDIA_PROXY_REQUIRE_CID_VERIFY", False):
        return True
    return _mode() == "prod"


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


def _cache_meta_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".meta.json")


def _cache_strict_reverify() -> bool:
    # Operators can force a full hash check on every cache hit.  By default the
    # observer trusts metadata that it wrote only after a prior successful byte
    # verification, which avoids rehashing large video files for every Range seek.
    return _env_bool("WEALL_MEDIA_CACHE_STRICT_REVERIFY", False)


def _read_cache_meta(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(_cache_meta_path(path).read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _write_cache_meta(*, cid: str, path: Path, verification: str, sha256_hex: str) -> None:
    try:
        meta = {
            "cid": str(cid),
            "size": int(path.stat().st_size),
            "sha256": str(sha256_hex or "").lower(),
            "verification": str(verification or ""),
            "verified_at_ms": int(time.time() * 1000),
        }
        meta_path = _cache_meta_path(path)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = meta_path.with_suffix(meta_path.suffix + ".tmp")
        tmp.write_text(json.dumps(meta, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        tmp.replace(meta_path)
    except Exception:
        # Metadata is a performance optimization.  Failure to write it must not
        # weaken integrity; future cache hits will fall back to full verification.
        return


def _remove_cache_artifacts(path: Path) -> None:
    for p in (path, _cache_meta_path(path)):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


def _cache_meta_verification(*, cid: str, path: Path, st: dict[str, Any] | None) -> str:
    if _cache_strict_reverify():
        return ""
    meta = _read_cache_meta(path)
    if not meta:
        return ""
    if str(meta.get("cid") or "") != str(cid):
        return ""
    try:
        if int(meta.get("size") or -1) != int(path.stat().st_size):
            return ""
    except Exception:
        return ""
    meta_sha = str(meta.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", meta_sha):
        return ""
    expected = _expected_sha256_for_cid(st, cid)
    if expected and not hmac.compare_digest(meta_sha, expected):
        return ""
    verification = str(meta.get("verification") or "cache_verified").strip() or "cache_verified"
    return verification


def _provider_url_from_base(base: str, cid: str) -> str:
    raw = str(base or "").strip()
    if not raw:
        return ""
    safe_cid = urllib.parse.quote(str(cid), safe="")
    if "{cid}" in raw:
        return raw.replace("{cid}", safe_cid)
    if raw.endswith("/v1/media/proxy"):
        return f"{raw}/{safe_cid}"
    if raw.endswith("/ipfs"):
        return f"{raw}/{safe_cid}"
    return f"{raw.rstrip('/')}/v1/media/proxy/{safe_cid}"


def _media_provider_url(cid: str) -> str:
    # Back-compat helper: first configured provider/gateway.
    return _media_provider_urls(cid)[0]


def _provider_urls_from_env(cid: str) -> list[str]:
    out: list[str] = []
    for name in ("WEALL_MEDIA_PROVIDER_URLS", "WEALL_MEDIA_PROVIDER_BASE_URLS"):
        raw = str(os.environ.get(name) or "").strip()
        if not raw:
            continue
        for item in raw.split(","):
            url = _provider_url_from_base(item.strip(), cid)
            if url and url not in out:
                out.append(url)
    return out


def _provider_urls_from_state(st: dict[str, Any] | None, cid: str) -> list[str]:
    if not isinstance(st, dict):
        return []
    out: list[str] = []
    storage = st.get("storage")
    if not isinstance(storage, dict):
        return []

    def _add(raw: Any) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        url = _provider_url_from_base(raw.strip(), cid)
        if url and url not in out:
            out.append(url)

    for bucket_name in ("pin_confirms", "pins", "providers"):
        bucket = storage.get(bucket_name)
        iterable = bucket.values() if isinstance(bucket, dict) else bucket if isinstance(bucket, list) else []
        for rec in iterable:
            if not isinstance(rec, dict):
                continue
            rec_cid = str(rec.get("cid") or rec.get("content_cid") or "").strip()
            if rec_cid and rec_cid != cid:
                continue
            for key in ("provider_url", "media_url", "gateway_url", "base_url", "endpoint"):
                _add(rec.get(key))
            node = rec.get("node") if isinstance(rec.get("node"), dict) else {}
            for key in ("provider_url", "media_url", "gateway_url", "base_url", "endpoint"):
                _add(node.get(key))
    return out


def _media_provider_urls(cid: str, st: dict[str, Any] | None = None) -> list[str]:
    out: list[str] = []
    for url in _provider_urls_from_env(cid) + _provider_urls_from_state(st, cid) + [ipfs_gateway_url(cid)]:
        if url and url not in out:
            out.append(url)
    return out


def _expected_sha256_for_cid(st: dict[str, Any] | None, cid: str) -> str:
    media = _content_media_index(st or {}) if isinstance(st, dict) else {}
    for _mid, raw in media.items():
        if not isinstance(raw, dict):
            continue
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        rec_cid = str(raw.get("cid") or payload.get("cid") or payload.get("upload_ref") or "").strip()
        if rec_cid != cid:
            continue
        for key in ("sha256", "content_sha256", "bytes_sha256", "digest_sha256"):
            v = str(payload.get(key) or raw.get(key) or "").strip().lower()
            if v.startswith("sha256:"):
                v = v.split(":", 1)[1]
            if re.fullmatch(r"[0-9a-f]{64}", v):
                return v
    return ""


def _verify_cached_media_bytes(*, cid: str, path: Path, st: dict[str, Any] | None) -> str:
    expected = _expected_sha256_for_cid(st, cid)
    data = path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if expected:
        if not hmac.compare_digest(actual_sha, expected):
            raise ApiError.bad_request(
                "media_byte_hash_mismatch",
                "media bytes did not match committed sha256",
                {"cid": cid, "expected": expected, "actual": actual_sha},
            )
        verification = "sha256"
        _write_cache_meta(cid=cid, path=path, verification=verification, sha256_hex=actual_sha)
        return verification

    cid_result = verify_cid_multihash_bytes(cid, data)
    if cid_result.ok:
        verification = cid_result.reason
        _write_cache_meta(cid=cid, path=path, verification=verification, sha256_hex=actual_sha)
        return verification

    if cid_result.supported:
        raise ApiError.bad_request(
            "media_cid_multihash_mismatch",
            "media bytes did not match CID multihash",
            {
                "cid": cid,
                "expected_digest": cid_result.expected_digest_hex,
                "actual_digest": cid_result.actual_digest_hex,
                "reason": cid_result.reason,
            },
        )

    if _media_integrity_required():
        raise ApiError.bad_request(
            "media_integrity_verification_unavailable",
            "media requires committed sha256 or a CID format this observer can verify directly",
            {"cid": cid, "reason": cid_result.reason},
        )
    verification = cid_result.reason or "not_configured"
    _write_cache_meta(cid=cid, path=path, verification=verification, sha256_hex=actual_sha)
    return verification



def _media_mime_for_cid(st: dict[str, Any] | None, cid: str) -> str:
    media = _content_media_index(st or {}) if isinstance(st, dict) else {}
    for _mid, raw in media.items():
        if not isinstance(raw, dict):
            continue
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        rec_cid = str(raw.get("cid") or payload.get("cid") or payload.get("upload_ref") or "").strip()
        if rec_cid != cid:
            continue
        mime = str(payload.get("mime") or payload.get("mime_type") or payload.get("content_type") or "").strip()
        if mime:
            return mime
    return "application/octet-stream"


def _parse_single_range_header(range_header: str, *, file_size: int) -> tuple[int, int] | None:
    raw = str(range_header or "").strip()
    if not raw:
        return None
    if not raw.lower().startswith("bytes="):
        raise ApiError.bad_request(
            "media_range_invalid",
            "only byte range requests are supported",
            {"range": raw},
        )
    spec = raw.split("=", 1)[1].strip()
    if not spec or "," in spec:
        raise ApiError.bad_request(
            "media_range_invalid",
            "only a single byte range is supported",
            {"range": raw},
        )
    if file_size <= 0:
        raise ApiError(416, "media_range_not_satisfiable", "media range is not satisfiable", {"range": raw, "size": int(file_size)})
    if "-" not in spec:
        raise ApiError.bad_request("media_range_invalid", "invalid byte range", {"range": raw})
    start_raw, end_raw = spec.split("-", 1)
    start_raw = start_raw.strip()
    end_raw = end_raw.strip()

    try:
        if start_raw == "":
            suffix_len = int(end_raw)
            if suffix_len <= 0:
                raise ValueError("invalid suffix range")
            start = max(0, file_size - suffix_len)
            end = file_size - 1
        else:
            start = int(start_raw)
            if start < 0:
                raise ValueError("invalid range start")
            end = int(end_raw) if end_raw else file_size - 1
            if end < start:
                raise ValueError("range end before start")
    except ValueError as exc:
        raise ApiError.bad_request("media_range_invalid", "invalid byte range", {"range": raw}) from exc

    if start >= file_size:
        raise ApiError(416, "media_range_not_satisfiable", "media range is not satisfiable", {"range": raw, "size": int(file_size)})
    end = min(end, file_size - 1)
    return int(start), int(end)


def _iter_file_range(path: Path, *, start: int, end: int, chunk_size: int = 64 * 1024):
    remaining = int(end) - int(start) + 1
    with path.open("rb") as f:
        f.seek(int(start))
        while remaining > 0:
            chunk = f.read(min(int(chunk_size), remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk


def _media_file_response(
    request: Request,
    *,
    cid: str,
    path: Path,
    st: dict[str, Any] | None,
    cache_state: str,
    verification: str,
    extra_headers: dict[str, str] | None = None,
):
    size = path.stat().st_size
    headers: dict[str, str] = {
        "Accept-Ranges": "bytes",
        "X-WeAll-Media-Cache": cache_state,
        "X-WeAll-Media-Load-Policy": "viewport",
        "X-WeAll-Media-Byte-Verified": verification,
    }
    if extra_headers:
        headers.update({str(k): str(v) for k, v in extra_headers.items()})

    range_tuple = _parse_single_range_header(request.headers.get("range", ""), file_size=int(size))
    media_type = _media_mime_for_cid(st, cid)
    if range_tuple is None:
        return FileResponse(path, media_type=media_type, headers=headers)

    start, end = range_tuple
    headers.update(
        {
            "Content-Range": f"bytes {start}-{end}/{size}",
            "Content-Length": str(end - start + 1),
            "X-WeAll-Media-Range": "1",
        }
    )
    return StreamingResponse(
        _iter_file_range(path, start=start, end=end),
        status_code=206,
        media_type=media_type,
        headers=headers,
    )

def _copy_provider_to_cache(*, cid: str, dest: Path, max_bytes: int, timeout_s: int, st: dict[str, Any] | None = None) -> tuple[int, str, str]:
    providers = _media_provider_urls(cid, st)
    tmp = dest.with_suffix(".tmp")
    dest.parent.mkdir(parents=True, exist_ok=True)
    last_error = ""

    for url in providers:
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

            verification = _verify_cached_media_bytes(cid=cid, path=tmp, st=st)
            tmp_meta = _read_cache_meta(tmp)
            tmp.replace(dest)
            tmp_sha = str(tmp_meta.get("sha256") or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", tmp_sha):
                _write_cache_meta(cid=cid, path=dest, verification=verification, sha256_hex=tmp_sha)
            else:
                # Fallback for older helpers/tests: still create destination
                # metadata after successful verification, even if the temp
                # metadata was unavailable. This may re-read once on first
                # provider fetch, but prevents repeated full-file hashing for
                # subsequent Range requests.
                _write_cache_meta(
                    cid=cid,
                    path=dest,
                    verification=verification,
                    sha256_hex=hashlib.sha256(dest.read_bytes()).hexdigest(),
                )
            try:
                _cache_meta_path(tmp).unlink(missing_ok=True)
            except Exception:
                pass
            return total, url, verification
        except ApiError as exc:
            last_error = str(exc)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            # Verification failures should not poison the cache. Try the next
            # provider if one exists, otherwise surface the fail-closed error.
            if "media_byte_hash" in str(exc) or "media_cid_multihash" in str(exc) or "media_integrity_verification" in str(exc):
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            continue

    raise ApiError.bad_request(
        "media_provider_unavailable",
        "media provider unavailable or failed verification",
        {"cid": cid, "providers": _provider_diagnostics(providers), "reason": last_error},
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




def _sha256_upload_file(upload: UploadFile, *, max_bytes: int) -> str:
    """Compute a file-byte sha256 without keeping the full upload in RAM."""
    digest = hashlib.sha256()
    total = 0
    try:
        upload.file.seek(0)
    except Exception:
        pass
    while True:
        chunk = upload.file.read(256 * 1024)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if max_bytes > 0 and total > max_bytes:
            raise ApiError.payload_too_large(
                "payload_too_large",
                "media upload exceeds local observer byte budget",
                {"bytes": total, "max_bytes": max_bytes},
            )
        digest.update(chunk)
    try:
        upload.file.seek(0)
    except Exception:
        pass
    return digest.hexdigest()

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
    """Upload a file, compute a streaming sha256, and store it on IPFS.

    Note: sha256 calculation is streaming/bounded, but the current IPFS HTTP
    adapter may still buffer the multipart upload internally within the enforced
    upload byte limit.

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

    sha256_hex = _sha256_upload_file(file, max_bytes=max_bytes)

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
        # Keep the suggested IPFS_PIN_REQUEST payload schema-clean.
        # File-byte commitments are returned below for CONTENT_MEDIA_DECLARE
        # and media verification, but IPFS_PIN_REQUEST currently accepts only
        # pin metadata such as cid and size_bytes.  Including sha256 here causes
        # strict tx payload validation to reject browser-driven create-post
        # flows before the media declaration can carry the commitment.
        "payload": {
            "cid": cid,
            "size_bytes": int(final_size) if int(final_size) > 0 else 0,
        },
        "upload_ref": cid,
        "ref": cid,
        "sig": "",
        "parent": None,
        "system": False,
    }
    pin_request["envelope"] = {
        **suggested_env,
        "payload": {
            **suggested_env["payload"],
            "sha256": sha256_hex,
        },
    }
    # Browser-facing compatibility keeps sha256 visible above, while actual
    # tx submission below still uses schema-clean `suggested_env`.
    pin_request["schema_safe_envelope"] = suggested_env

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
        "sha256": sha256_hex,
        "content_sha256": sha256_hex,
        "bytes_sha256": sha256_hex,
        "uri": f"ipfs://{cid}",
        "gateway_url": ipfs_gateway_url(cid),
        "pinned_on_upload": bool(pin_on_upload),
        "pin_request": pin_request,
        "media_declare_defaults": {
            "cid": cid,
            "upload_ref": cid,
            "mime": mime,
            "bytes": int(final_size),
            "name": name,
            "sha256": sha256_hex,
        },
    }


@router.get("/media/gateway/{cid}")
async def v1_media_gateway(cid: str):
    """Legacy CID gateway route.

    Production posture routes legacy callers through the local observer proxy so
    byte verification, cache policy, and provider redaction remain in force. A
    direct external gateway redirect is available only by explicit operator opt-in.
    """
    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)
    if _mode() == "prod" and not _env_bool("WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT", False):
        return RedirectResponse(f"/v1/media/proxy/{v.cid}")
    return RedirectResponse(ipfs_gateway_url(v.cid))


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


@router.get("/media/providers/{cid}")
def v1_media_providers(request: Request, cid: str):
    """Return ordered provider candidates for a CID without fetching bytes.

    Production posture: provider URLs can reveal LAN/internal topology.  Public
    callers receive provider kind summaries unless URL exposure is explicitly
    enabled or the request has operator authorization.
    """
    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)
    st = _snapshot(request)
    urls = _media_provider_urls(v.cid, st)
    expose_urls = _media_provider_urls_public() or _request_has_media_operator_auth(request)
    if expose_urls:
        providers: list[Any] = urls
    else:
        providers = [{"kind": _provider_kind(url), "redacted": True} for url in urls]
    return {
        "ok": True,
        "cid": v.cid,
        "providers": providers,
        "count": len(urls),
        "urls_redacted": not expose_urls,
    }


@router.get("/media/proxy/{cid}")
def v1_media_proxy(request: Request, cid: str):
    """Serve media through the local observer with bounded cache/fetch policy.

    Feed/list endpoints never call this. The frontend should request this only
    when a media card enters or approaches the viewport. The observer mediates
    provider fetch, byte budget, concurrency, and local cache.
    """
    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.invalid("invalid_payload", v.reason)

    normalized_cid = v.cid
    st = _snapshot(request)
    max_bytes = max(1, _env_int("WEALL_MEDIA_PROXY_MAX_BYTES", 25 * 1024 * 1024))
    timeout_s = max(1, _env_int("WEALL_MEDIA_PROXY_TIMEOUT_S", 20))
    inflight = max(1, _env_int("WEALL_MEDIA_PROXY_MAX_INFLIGHT", 4))

    if not _cache_enabled():
        # Redirecting directly to a provider bypasses observer byte verification.
        # Production observers must fail closed unless the operator explicitly
        # allows the weaker redirect behavior for a controlled deployment.
        if not _allow_unverified_media_redirect():
            raise ApiError.forbidden(
                "media_unverified_redirect_forbidden",
                "media proxy cache-disabled redirect bypasses observer integrity verification",
                {"cid": normalized_cid},
            )
        return RedirectResponse(_media_provider_urls(normalized_cid, st)[0])

    path = _cache_path_for_cid(normalized_cid)
    if path.exists() and path.is_file():
        verification = _cache_meta_verification(cid=normalized_cid, path=path, st=st)
        if not verification:
            try:
                verification = _verify_cached_media_bytes(cid=normalized_cid, path=path, st=st)
            except ApiError:
                _remove_cache_artifacts(path)
                verification = ""
        if verification:
            return _media_file_response(
                request,
                cid=normalized_cid,
                path=path,
                st=st,
                cache_state="hit",
                verification=verification,
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
        _bytes, provider, verification = _copy_provider_to_cache(cid=normalized_cid, dest=path, max_bytes=max_bytes, timeout_s=timeout_s, st=st)
    finally:
        sem.release()

    return _media_file_response(
        request,
        cid=normalized_cid,
        path=path,
        st=st,
        cache_state="miss-store",
        verification=verification,
        extra_headers={
            "X-WeAll-Media-Provider-Kind": _provider_kind(provider),
            "X-WeAll-Media-Provider-Redacted": "1",
        },
    )
