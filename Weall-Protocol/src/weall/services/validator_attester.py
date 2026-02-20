from __future__ import annotations

import argparse
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from weall.crypto.sig import sign_tx_envelope_dict

Json = Dict[str, Any]


def _http_json(method: str, url: str, body: Optional[Json] = None, timeout_s: float = 10.0) -> Json:
    method = method.upper().strip()
    headers = {"Content-Type": "application/json"}
    data: Optional[bytes] = None

    if body is not None:
        import json

        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        import json

        try:
            return json.loads(raw)
        except Exception:
            return {"ok": False, "error": "bad_json", "raw": raw}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        try:
            import json

            return json.loads(raw)
        except Exception:
            pass
        return {"ok": False, "error": "http_error", "status": int(getattr(e, "code", 0) or 0), "raw": raw}
    except urllib.error.URLError as e:
        return {"ok": False, "error": "url_error", "reason": str(getattr(e, "reason", e))}


def _read_secret(path: str) -> str:
    return open(path, "r", encoding="utf-8").read().strip()


def run_attester_loop(
    *,
    producer_url: str,
    signer: str,
    privkey: str,
    poll_seconds: float,
    encoding: str,
    once: bool,
    verbose: bool,
) -> int:
    producer_url = producer_url.rstrip("/")

    last_tip: Optional[str] = None

    while True:
        snap = _http_json("GET", f"{producer_url}/v1/state/snapshot")
        if not snap.get("ok"):
            if verbose:
                print("snapshot_error:", snap)
            time.sleep(poll_seconds)
            if once:
                return 2
            continue

        tip = str(snap.get("tip") or "").strip()
        tip_proposal_id = str(snap.get("tip_proposal_id") or "").strip()
        tip_round = int(snap.get("tip_round", 0) or 0)
        height = int(snap.get("height", 0) or 0)

        # Source checkpoint for Casper-style justification/finality.
        source_block_id = (
            str(snap.get("justified_block_id") or "").strip()
            or str(snap.get("finalized_block_id") or "").strip()
        )
        try:
            source_height = int(snap.get("justified_height", 0) or 0)
        except Exception:
            source_height = 0
        if not source_block_id:
            source_block_id = str(snap.get("finalized_block_id") or "").strip()
            try:
                source_height = int(snap.get("finalized_height", 0) or 0)
            except Exception:
                source_height = 0

        if not tip:
            if verbose:
                print("no_tip_yet height=", height)
            time.sleep(poll_seconds)
            if once:
                return 0
            continue

        if tip == last_tip:
            time.sleep(poll_seconds)
            if once:
                return 0
            continue

        # Fetch current nonce so we can produce next nonce.
        nonce_doc = _http_json("GET", f"{producer_url}/v1/accounts/{signer}/nonce")
        if not nonce_doc.get("ok"):
            if verbose:
                print("nonce_error:", nonce_doc)
            time.sleep(poll_seconds)
            if once:
                return 2
            continue

        cur_nonce = int(nonce_doc.get("nonce", 0) or 0)
        next_nonce = cur_nonce + 1

        payload: Json = {
            "block_id": tip,
            "height": int(height),
            "round": int(tip_round),
            "source_block_id": source_block_id,
            "source_height": int(source_height),
        }
        if tip_proposal_id:
            payload["proposal_id"] = tip_proposal_id

        tx: Json = {
            "tx_type": "BLOCK_ATTEST",
            "signer": signer,
            "nonce": next_nonce,
            "payload": payload,
            "system": False,
        }
        tx = sign_tx_envelope_dict(tx=tx, privkey=privkey, encoding=encoding)

        res = _http_json("POST", f"{producer_url}/v1/consensus/attest/submit", body=tx)
        if verbose:
            print(
                "attest",
                {
                    "tip": tip,
                    "height": height,
                    "round": tip_round,
                    "proposal_id": tip_proposal_id,
                    "source_block_id": source_block_id,
                    "source_height": int(source_height),
                    "nonce": next_nonce,
                    "ok": bool(res.get("ok")),
                    "code": res.get("code"),
                },
            )

        last_tip = tip

        if once:
            return 0
        time.sleep(poll_seconds)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="WeAll validator attester (poll head, submit signed BLOCK_ATTEST)")
    p.add_argument("--producer-url", default=os.environ.get("WEALL_PRODUCER_URL", "http://127.0.0.1:8000"))
    p.add_argument("--signer", default=os.environ.get("WEALL_VALIDATOR_ACCOUNT", "val1"))
    p.add_argument("--privkey", default=os.environ.get("WEALL_VALIDATOR_PRIVKEY", ""))
    p.add_argument("--privkey-file", default=os.environ.get("WEALL_VALIDATOR_PRIVKEY_FILE", ""))
    p.add_argument("--encoding", default=os.environ.get("WEALL_SIG_ENCODING", "hex"))
    p.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_ATTEST_POLL_SECONDS", "3")))
    p.add_argument("--once", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    priv = (args.privkey or "").strip()
    if not priv and (args.privkey_file or "").strip():
        priv = _read_secret((args.privkey_file or "").strip())

    if not priv:
        print("missing privkey: set WEALL_VALIDATOR_PRIVKEY or --privkey / --privkey-file")
        return 2

    return run_attester_loop(
        producer_url=str(args.producer_url),
        signer=str(args.signer),
        privkey=priv,
        poll_seconds=max(0.5, float(args.poll)),
        encoding=str(args.encoding),
        once=bool(args.once),
        verbose=bool(args.verbose),
    )


if __name__ == "__main__":
    raise SystemExit(main())
