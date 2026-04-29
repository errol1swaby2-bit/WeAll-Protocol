# src/weall/api/__main__.py
from __future__ import annotations

import os

import uvicorn

from weall.env import load_dotenv_if_present


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return str(default)
    try:
        s = str(raw)
    except Exception:
        if _mode() == "prod":
            raise ValueError(f"invalid_string_env:{name}")
        return str(default)
    if s == "":
        return str(default)
    return s


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    try:
        s = str(raw).strip()
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)
    if s == "":
        return int(default)
    try:
        return int(s)
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def main() -> None:
    # Load .env early so WEALL_* vars exist before anything reads them.
    load_dotenv_if_present()

    # Import after dotenv load (prevents "config read before env" surprises)
    from weall.api.app import create_app

    host = _env_str("WEALL_API_HOST", "127.0.0.1")
    port = _env_int("WEALL_API_PORT", 8080)

    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
