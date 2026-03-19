from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO

Json = dict[str, object]


@dataclass(frozen=True)
class IpfsConfig:
    api_base: str
    gateway_base: str


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _validated_url_base(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        candidate = str(default).strip()
    else:
        candidate = str(raw).strip()
        if candidate == "":
            if _mode() == "prod":
                raise ValueError(f"invalid_url_env:{name}")
            candidate = str(default).strip()
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        if _mode() == "prod" and raw is not None:
            raise ValueError(f"invalid_url_env:{name}")
        if raw is None:
            parsed_default = urllib.parse.urlparse(str(default).strip())
            if parsed_default.scheme not in {"http", "https"} or not parsed_default.netloc:
                raise ValueError(f"invalid_url_env:{name}")
        candidate = str(default).strip()
    return candidate.rstrip("/")


def _cfg() -> IpfsConfig:
    api_base = _validated_url_base("WEALL_IPFS_API_BASE", "http://127.0.0.1:5001")
    gateway_base = _validated_url_base("WEALL_IPFS_GATEWAY_BASE", "http://127.0.0.1:8080")
    return IpfsConfig(api_base=api_base, gateway_base=gateway_base)


def ipfs_gateway_url(cid: str) -> str:
    cid = (cid or "").strip()
    if not cid:
        return ""
    cfg = _cfg()
    if not cfg.gateway_base:
        return ""
    return f"{cfg.gateway_base}/ipfs/{cid}"


def _parse_ipfs_add_response(raw: bytes) -> tuple[str, int]:
    """
    IPFS /api/v0/add returns NDJSON (one JSON object per line).
    We take the last valid JSON object and extract Hash + Size.
    """
    txt = raw.decode("utf-8", errors="replace").strip()
    if not txt:
        raise RuntimeError("ipfs_add_failed:empty_response")

    last_obj: dict | None = None
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            last_obj = obj

    if not isinstance(last_obj, dict):
        raise RuntimeError(f"ipfs_add_failed:bad_response:{txt[:200]}")

    cid = str(last_obj.get("Hash") or "").strip()
    size_s = str(last_obj.get("Size") or "0").strip()
    try:
        size = int(size_s)
    except Exception:
        size = 0

    if not cid:
        raise RuntimeError(f"ipfs_add_failed:missing_hash:{last_obj!r}")

    return cid, size


def _read_all_bytes(fileobj: BinaryIO) -> bytes:
    try:
        fileobj.seek(0)
    except Exception:
        pass

    parts: list[bytes] = []
    while True:
        chunk = fileobj.read(1024 * 256)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        parts.append(chunk)
    return b"".join(parts)


def ipfs_add_fileobj(*, name: str, fileobj: BinaryIO, pin: bool) -> tuple[str, int]:
    """
    Upload a file-like object to IPFS via /api/v0/add.

    This implementation intentionally uses a standard fixed-length multipart
    request body because the previous low-level streaming implementations caused
    connection resets / 400s against the current Kubo setup.

    Returns:
      (cid, size)
    """
    cfg = _cfg()
    if not cfg.api_base:
        raise RuntimeError("ipfs_disabled:WEALL_IPFS_API_BASE is empty")

    filename = (name or "upload").strip() or "upload"
    file_bytes = _read_all_bytes(fileobj)

    boundary = "----weall-ipfs-boundary-7b3f2d6f9a3a4b8a"
    preamble = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
    ).encode()
    epilogue = f"\r\n--{boundary}--\r\n".encode()
    body = preamble + file_bytes + epilogue

    qs = urllib.parse.urlencode(
        {
            "pin": "true" if pin else "false",
            "wrap-with-directory": "false",
            "progress": "false",
        }
    )
    url = f"{cfg.api_base}/api/v0/add?{qs}"

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return _parse_ipfs_add_response(raw)
    except urllib.error.HTTPError as e:
        raw = e.read()
        msg = raw.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"ipfs_add_failed:http_{e.code}:{msg[:300]}")
    except Exception as e:
        raise RuntimeError(f"ipfs_add_failed:{type(e).__name__}:{e}") from e


def ipfs_add_bytes(*, name: str, data: bytes, pin: bool) -> tuple[str, int]:
    """
    Backward-compatible helper: adds bytes to IPFS.
    """
    bio = BytesIO(data)
    return ipfs_add_fileobj(name=name, fileobj=bio, pin=pin)
