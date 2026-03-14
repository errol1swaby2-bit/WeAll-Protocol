# src/weall/env.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_LOADED = False


def load_dotenv_if_present(dotenv_path: Optional[str] = None) -> bool:
    """
    Best-effort .env loader.

    - Safe in prod: if python-dotenv isn't installed, this is a no-op.
    - Deterministic: loads once per process.
    - Path rules:
        1) If dotenv_path arg provided, use it.
        2) Else if WEALL_DOTENV_PATH is set, use that.
        3) Else default to ".env" in current working directory.

    Returns True if a dotenv file was found AND loaded, else False.
    """
    global _LOADED
    if _LOADED:
        return False

    path_s = dotenv_path or os.getenv("WEALL_DOTENV_PATH", ".env")
    try:
        path = Path(path_s).expanduser()
    except Exception:
        _LOADED = True
        return False

    if not path.exists() or not path.is_file():
        _LOADED = True
        return False

    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        # python-dotenv not installed (allowed)
        _LOADED = True
        return False

    load_dotenv(dotenv_path=str(path), override=False)
    _LOADED = True
    return True
