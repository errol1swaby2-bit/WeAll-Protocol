import os
from dataclasses import dataclass
import json
from pathlib import Path
from urllib.parse import urlparse, urlunparse


@dataclass(frozen=True)
class ApiConfig:
    mode: str  # "gateway" | "node"
    nodes_registry_token: str | None
    nodes_registry_path: str | None


def load_api_config() -> ApiConfig:
    mode = os.getenv("WEALL_API_MODE", "gateway").strip().lower()
    token = os.getenv("WEALL_NODES_REGISTRY_TOKEN")
    path = os.getenv("WEALL_NODES_REGISTRY_PATH")
    return ApiConfig(mode=mode, nodes_registry_token=token, nodes_registry_path=path)


def read_nodes_registry(path: str | None) -> dict:
    """
    Read the gateway node registry JSON.

    Expected shape:
      {"version": 1, "nodes": [{"base_url": "...", "role": "...", "region": "...", "weight": 0}, ...]}

    Fail-closed:
      - missing/invalid file yields {"version": 1, "nodes": []}
    """
    try:
        if not path:
            return {"version": 1, "nodes": []}
        p = Path(path)
        if not p.exists() or not p.is_file():
            return {"version": 1, "nodes": []}
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"version": 1, "nodes": []}
        if not isinstance(data.get("nodes"), list):
            data["nodes"] = []
        if "version" not in data:
            data["version"] = 1
        return data
    except Exception:
        return {"version": 1, "nodes": []}


def _is_truthy(v: str | None) -> bool:
    if v is None:
        return False
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def allow_insecure_localhost(mode: str) -> bool:
    """
    Dev convenience: allow http://localhost and http://127.0.0.1 as node base URLs.
    Still requires HTTPS for everything else.
    """
    env = os.getenv("WEALL_ALLOW_INSECURE_LOCALHOST")
    if env is not None:
        return _is_truthy(env)
    # Default: allow in non-prod-ish modes
    return mode != "prod"


def normalize_base_url(url: str, *, allow_insecure_localhost_urls: bool) -> str:
    """
    Normalize and validate a base URL.

    Rules:
      - Must be https://... OR (if allow_insecure_localhost_urls) http://localhost/... or http://127.0.0.1/...
      - Strips trailing slashes
      - Keeps port if provided
      - Rejects query/fragment
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("base_url must be a non-empty string")

    parsed = urlparse(url.strip())

    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not include query or fragment")

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme == "https":
        pass
    elif scheme == "http" and allow_insecure_localhost_urls and host in {"localhost", "127.0.0.1"}:
        pass
    else:
        raise ValueError("base_url must be https (or http localhost in dev)")

    if not host:
        raise ValueError("base_url must include a hostname")

    # Normalize path: keep only "/" or empty
    path = parsed.path or ""
    if path not in {"", "/"}:
        # base_url should be origin-level, not a subpath
        raise ValueError("base_url must not include a path (use origin only)")

    normalized = urlunparse(
        (
            scheme,
            parsed.netloc,
            "",  # path
            "",  # params
            "",  # query
            "",  # fragment
        )
    ).rstrip("/")

    return normalized
