# src/weall/env.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_LOADED = False


class DotenvConfigError(RuntimeError):
    """Raised when operator-supplied dotenv configuration is unusable in prod."""


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def load_dotenv_if_present(dotenv_path: Optional[str] = None) -> bool:
    """
    Load an operator-configured .env file when present.

    Behavior:
    - Deterministic: loads at most once per process.
    - If no explicit dotenv path is supplied, a missing default ".env" is a no-op.
    - In prod, an explicitly configured dotenv path must be usable; malformed or
      unreadable operator input raises instead of silently disappearing.

    Path rules:
        1) If dotenv_path arg provided, use it.
        2) Else if WEALL_DOTENV_PATH is set, use that.
        3) Else default to ".env" in current working directory.

    Returns True if a dotenv file was found AND loaded, else False.
    """
    global _LOADED
    if _LOADED:
        return False

    explicit_path_supplied = dotenv_path is not None or os.getenv("WEALL_DOTENV_PATH") is not None
    path_s = dotenv_path if dotenv_path is not None else os.getenv("WEALL_DOTENV_PATH", ".env")

    try:
        path = Path(str(path_s)).expanduser()
    except Exception as exc:
        _LOADED = True
        if explicit_path_supplied and _is_prod():
            raise DotenvConfigError("dotenv_path_invalid") from exc
        return False

    if not path.exists():
        _LOADED = True
        if explicit_path_supplied and _is_prod():
            raise DotenvConfigError("dotenv_path_missing")
        return False

    if not path.is_file():
        _LOADED = True
        if explicit_path_supplied and _is_prod():
            raise DotenvConfigError("dotenv_path_not_file")
        return False

    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception as exc:
        _LOADED = True
        if explicit_path_supplied and _is_prod():
            raise DotenvConfigError("dotenv_dependency_missing") from exc
        return False

    try:
        load_dotenv(dotenv_path=str(path), override=False)
    except Exception as exc:
        _LOADED = True
        if explicit_path_supplied and _is_prod():
            raise DotenvConfigError("dotenv_load_failed") from exc
        return False

    _LOADED = True
    return True
