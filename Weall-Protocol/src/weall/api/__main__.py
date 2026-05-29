# src/weall/api/__main__.py
from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m weall.api",
        description="Start the WeAll Node API."
    )
    parser.add_argument(
        "--host",
        default=_env_str("WEALL_API_HOST", "127.0.0.1"),
        help="API bind host; defaults to WEALL_API_HOST or 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=_env_int("WEALL_API_PORT", 8080),
        help="API bind port; defaults to WEALL_API_PORT or 8080.",
    )

    runtime = parser.add_mutually_exclusive_group()
    runtime.add_argument(
        "--boot-runtime",
        dest="boot_runtime",
        action="store_true",
        default=None,
        help="Force runtime/executor boot even when WEALL_API_BOOT_RUNTIME is unset.",
    )
    runtime.add_argument(
        "--no-boot-runtime",
        dest="boot_runtime",
        action="store_false",
        help="Start the API shell without booting runtime/executor state.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    # Load .env early so WEALL_* vars exist before anything reads them.
    load_dotenv_if_present()

    parser = _build_parser()
    args = parser.parse_args(argv)

    # Import after dotenv load and CLI parsing. This keeps `python -m weall.api
    # --help` lightweight and preserves the existing app-level runtime default.
    from weall.api.app import create_app, _module_app_boot_runtime_default

    boot_runtime = (
        bool(args.boot_runtime)
        if args.boot_runtime is not None
        else _module_app_boot_runtime_default()
    )

    uvicorn.run(
        create_app(boot_runtime=boot_runtime),
        host=str(args.host),
        port=int(args.port),
        log_level="info",
    )


if __name__ == "__main__":
    main()
