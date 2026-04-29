#!/usr/bin/env python3
"""Client for the WeAll API mediated PoH email verification flow."""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

Json = dict[str, Any]


def _post_json(base_url: str, path: str, body: Json, timeout_s: int) -> Json:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(
        url,
        data=json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        headers={"accept": "application/json", "content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"http_error:{exc.code}:{raw}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"request_failed:{exc}") from exc
    parsed = json.loads(raw or "{}")
    if not isinstance(parsed, dict):
        raise SystemExit("response_not_object")
    return parsed


def cmd_start(args: argparse.Namespace) -> Json:
    return _post_json(
        args.api_base,
        "/v1/poh/email/begin",
        {"account": args.account, "email": args.email},
        args.timeout,
    )


def cmd_complete(args: argparse.Namespace) -> Json:
    return _post_json(
        args.api_base,
        "/v1/poh/email/complete",
        {
            "account": args.account,
            "email": args.email,
            "request_id": args.request_id,
            "code": args.code,
        },
        args.timeout,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=int, default=10)
    sub = parser.add_subparsers(dest="cmd", required=True)
    start = sub.add_parser("start")
    start.add_argument("--account", required=True)
    start.add_argument("--email", required=True)
    complete = sub.add_parser("complete")
    complete.add_argument("--account", required=True)
    complete.add_argument("--email", required=True)
    complete.add_argument("--request-id", required=True)
    complete.add_argument("--code", required=True)
    args = parser.parse_args(argv)
    result = cmd_start(args) if args.cmd == "start" else cmd_complete(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
