import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse


class ApiConfigError(RuntimeError):
    """Raised when operator-supplied API config is malformed in prod."""


class NodesRegistryConfigError(RuntimeError):
    """Raised when an explicitly configured nodes registry is malformed in prod."""


@dataclass(frozen=True)
class ApiConfig:
    mode: str  # "gateway" | "node" | free-form deployment mode tag
    nodes_registry_token: str | None
    nodes_registry_path: str | None


_EMPTY_REGISTRY = {"version": 1, "nodes": []}


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def load_api_config() -> ApiConfig:
    mode = str(os.getenv("WEALL_API_MODE", "gateway") or "gateway").strip().lower() or "gateway"
    token_raw = os.getenv("WEALL_NODES_REGISTRY_TOKEN")
    path_raw = os.getenv("WEALL_NODES_REGISTRY_PATH")

    token = str(token_raw).strip() if token_raw is not None else None
    if token == "":
        token = None

    path = str(path_raw).strip() if path_raw is not None else None
    if path == "":
        path = None

    if _is_prod() and path_raw is not None and path is None:
        raise ApiConfigError("api_nodes_registry_path_empty")

    return ApiConfig(mode=mode, nodes_registry_token=token, nodes_registry_path=path)


def read_nodes_registry(path: str | None) -> dict:
    """
    Read the gateway node registry JSON.

    Expected shape:
      {"version": 1, "nodes": [{"base_url": "...", "role": "...", "region": "...", "weight": 0}, ...]}

    Fail-closed in prod for explicitly configured registries:
      - missing file
      - non-file path
      - invalid JSON
      - non-object top-level JSON
      - invalid nodes/version shapes

    For absent/unconfigured registry paths, or non-prod posture, returns an empty
    registry instead of aborting.
    """
    if not path:
        return dict(_EMPTY_REGISTRY)

    p = Path(path)
    strict = _is_prod()

    try:
        if not p.exists():
            if strict:
                raise NodesRegistryConfigError("nodes_registry_missing")
            return dict(_EMPTY_REGISTRY)
        if not p.is_file():
            if strict:
                raise NodesRegistryConfigError("nodes_registry_not_file")
            return dict(_EMPTY_REGISTRY)

        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            if strict:
                raise NodesRegistryConfigError("nodes_registry_not_object")
            return dict(_EMPTY_REGISTRY)

        version = data.get("version", 1)
        if not isinstance(version, int):
            if strict:
                raise NodesRegistryConfigError("nodes_registry_bad_version")
            version = 1

        nodes = data.get("nodes", [])
        if not isinstance(nodes, list):
            if strict:
                raise NodesRegistryConfigError("nodes_registry_bad_nodes")
            nodes = []

        out_nodes: list[dict] = []
        for entry in nodes:
            if not isinstance(entry, dict):
                if strict:
                    raise NodesRegistryConfigError("nodes_registry_bad_node_entry")
                continue
            out_nodes.append(dict(entry))

        return {"version": int(version), "nodes": out_nodes}
    except NodesRegistryConfigError:
        raise
    except json.JSONDecodeError as exc:
        if strict:
            raise NodesRegistryConfigError("nodes_registry_bad_json") from exc
        return dict(_EMPTY_REGISTRY)
    except Exception as exc:
        if strict:
            raise NodesRegistryConfigError("nodes_registry_read_failed") from exc
        return dict(_EMPTY_REGISTRY)


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
