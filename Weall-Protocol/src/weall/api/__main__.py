# src/weall/api/__main__.py
from __future__ import annotations

import os

import uvicorn

from weall.env import load_dotenv_if_present


def main() -> None:
    # Load .env early so WEALL_* vars exist before anything reads them.
    load_dotenv_if_present()

    # Import after dotenv load (prevents "config read before env" surprises)
    from weall.api.app import create_app

    host = os.getenv("WEALL_API_HOST", "127.0.0.1")
    port = int(os.getenv("WEALL_API_PORT", "8080"))

    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
