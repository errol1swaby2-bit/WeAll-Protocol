#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Any


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - operator utility against explicit local/remote URL
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def main() -> int:
    base = str(os.environ.get("WEALL_API_BASE_URL") or "http://127.0.0.1:8000").rstrip("/")
    url = f"{base}/v1/status/consensus/forensics"
    try:
        payload = _get_json(url)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": "fetch_failed", "url": url, "details": str(exc)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
