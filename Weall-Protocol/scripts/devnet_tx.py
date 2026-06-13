#!/usr/bin/env python3
"""Controlled-devnet transaction helper.

This helper intentionally uses normal public API routes only. It does not call
seeded-demo endpoints, does not mutate local databases, and does not bypass
signature, nonce, mempool, consensus, execution, or receipt paths.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from nacl.signing import SigningKey  # noqa: E402

from weall.crypto.sig import sign_tx_envelope_dict  # noqa: E402

Json = dict[str, Any]


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _normalize_account(value: str | None, *, fallback_pubkey: str = "", existing: str = "") -> str:
    explicit = str(value or "").strip()
    if explicit:
        return explicit
    old = str(existing or "").strip()
    if old:
        return old
    pub = str(fallback_pubkey or "").strip()
    suffix = pub[:12] if pub else _sha256_hex(str(_now_ms()).encode("utf-8"))[:12]
    return f"@devnet-{suffix}"


def _seed_bytes_from_private_hex(private_key_hex: str) -> bytes:
    raw = bytes.fromhex(str(private_key_hex or "").strip())
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("private_key_hex must be a 32-byte seed or 64-byte expanded key")
    return raw


def _derive_public_key_hex(private_key_hex: str) -> str:
    return SigningKey(_seed_bytes_from_private_hex(private_key_hex)).verify_key.encode().hex()


def _new_keypair() -> tuple[str, str]:
    sk = SigningKey.generate()
    return sk.encode().hex(), sk.verify_key.encode().hex()


def _key_material(keyfile: Path, *, account: str = "", fresh: bool = False) -> tuple[str, str, str, Json]:
    """Load or create controlled-devnet Ed25519 key material.

    The helper is intentionally file-backed so shell harnesses can share one
    account/key across create-account, native PoH verification, and
    tick commands without relying on seeded-demo mutation routes.
    """

    keyfile = Path(keyfile).expanduser()
    keyfile.parent.mkdir(parents=True, exist_ok=True)

    data: Json = {}
    if keyfile.exists() and not fresh:
        try:
            loaded = json.loads(keyfile.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception as exc:
            raise SystemExit(f"failed to read keyfile {keyfile}: {exc}") from exc

    priv = str(data.get("private_key_hex") or "").strip()
    pub = str(data.get("public_key_hex") or "").strip()

    if fresh or not priv:
        priv, pub = _new_keypair()
    else:
        try:
            derived_pub = _derive_public_key_hex(priv)
        except Exception as exc:
            raise SystemExit(f"invalid private_key_hex in {keyfile}: {exc}") from exc
        if not pub:
            pub = derived_pub
        elif pub != derived_pub:
            raise SystemExit(f"public_key_hex does not match private_key_hex in {keyfile}")

    acct = _normalize_account(account, fallback_pubkey=pub, existing=str(data.get("account") or ""))
    out: Json = dict(data)
    out.update(
        {
            "account": acct,
            "private_key_hex": priv,
            "public_key_hex": pub,
            "key_type": "ed25519",
        }
    )
    if "created_at_ms" not in out:
        out["created_at_ms"] = _now_ms()
    out["updated_at_ms"] = _now_ms()
    keyfile.write_text(_json_dumps(out) + "\n", encoding="utf-8")
    try:
        keyfile.chmod(0o600)
    except OSError:
        pass
    return acct, priv, pub, out


def _load_json_arg(value: str) -> Json:
    raw = str(value or "").strip()
    if not raw:
        raise SystemExit("missing JSON object")
    if raw.startswith("@"):
        path = Path(raw[1:]).expanduser()
        raw = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("JSON payload must be an object")
    return parsed


def _http_json(method: str, api: str, path: str, body: Json | None = None, *, timeout: float = 20.0) -> Json:
    base = str(api or "").strip().rstrip("/")
    if not base:
        raise SystemExit("missing API base URL")
    suffix = str(path or "").strip()
    if not suffix.startswith("/"):
        suffix = "/" + suffix
    url = base + suffix

    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method=str(method or "GET").upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - controlled local/devnet helper
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code} {method.upper()} {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"request failed {method.upper()} {url}: {exc}") from exc

    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"non-JSON response from {url}: {raw[:500]}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit(f"expected JSON object from {url}: {parsed!r}")
    return parsed


def _chain_id(api: str) -> str:
    ident = _http_json("GET", api, "/v1/chain/identity")
    chain_id = str(ident.get("chain_id") or "").strip()
    if not chain_id:
        raise SystemExit(f"chain identity response missing chain_id: {_json_dumps(ident)}")
    return chain_id


def _account_state(api: str, account: str) -> Json:
    quoted = urllib.parse.quote(str(account or "").strip(), safe="")
    out = _http_json("GET", api, f"/v1/accounts/{quoted}")
    state = out.get("state") if isinstance(out.get("state"), dict) else None
    return state if isinstance(state, dict) else {}


def _next_nonce(api: str, account: str) -> int:
    state = _account_state(api, account)
    try:
        return int(state.get("nonce") or 0) + 1
    except Exception:
        return 1


def _sign_tx(
    *,
    chain_id: str,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    parent: str | None,
    privkey: str,
) -> Json:
    tx: Json = {
        "chain_id": str(chain_id or "").strip(),
        "tx_type": str(tx_type or "").strip().upper(),
        "signer": str(signer or "").strip(),
        "nonce": int(nonce),
        "payload": payload if isinstance(payload, dict) else {},
    }
    if parent is not None:
        tx["parent"] = str(parent)
    return sign_tx_envelope_dict(tx=tx, privkey=privkey, encoding="hex")


def _wait_tx(api: str, tx_id: str, *, timeout_s: float, poll_s: float) -> Json:
    deadline = time.time() + max(0.0, float(timeout_s))
    last: Json = {"ok": False, "tx_id": str(tx_id or ""), "status": "unknown"}
    while True:
        last = _http_json("GET", api, f"/v1/tx/status/{urllib.parse.quote(str(tx_id or ''), safe='')}")
        status = str(last.get("status") or "").strip().lower()
        if status == "confirmed":
            return last
        if time.time() >= deadline:
            out = dict(last)
            out["timed_out"] = True
            return out
        time.sleep(max(0.05, float(poll_s)))


def cmd_ensure_keyfile(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    account, _priv, pub, data = _key_material(keyfile, account=args.account)
    if args.print_private:
        out: Json = dict(data)
    else:
        out = {"account": account, "public_key_hex": pub, "keyfile": str(keyfile)}
    print(_json_dumps({"ok": True, **out}))
    return 0


def cmd_create_account(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    account, priv, pub, keydata = _key_material(keyfile, account=args.account, fresh=bool(args.fresh))
    chain_id = _chain_id(args.api)

    skeleton = _http_json(
        "POST",
        args.api,
        "/v1/accounts/tx/register",
        {"account_id": account, "pubkey": pub, "parent": args.parent},
    )
    tx_skel = skeleton.get("tx") if isinstance(skeleton, dict) else None
    if not isinstance(tx_skel, dict):
        raise SystemExit(f"Unexpected register skeleton response: {_json_dumps(skeleton)}")

    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type="ACCOUNT_REGISTER",
        signer=account,
        nonce=nonce,
        payload=tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else {"pubkey": pub},
        parent=args.parent,
        privkey=priv,
    )
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    result: Json = {
        "ok": bool(submitted.get("ok", False)),
        "api": args.api,
        "chain_id": chain_id,
        "account": account,
        "keyfile": str(keyfile),
        "public_key_hex": pub,
        "tx_id": tx_id,
        "submit": submitted,
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_account_register_tx_id"] = tx_id
    keydata["chain_id"] = chain_id
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    print(_json_dumps(result))
    return 0


def cmd_submit_tx(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    account, priv, _pub, _data = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    payload = _load_json_arg(args.payload_json)
    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type=args.tx_type,
        signer=account,
        nonce=nonce,
        payload=payload,
        parent=args.parent,
        privkey=priv,
    )
    tx_out = str(getattr(args, "tx_out", "") or "").strip()
    if tx_out:
        out_path = Path(tx_out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_json_dumps(tx) + "\n", encoding="utf-8")
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    result: Json = {
        "ok": bool(submitted.get("ok", False)),
        "api": args.api,
        "chain_id": chain_id,
        "account": account,
        "tx_id": tx_id,
        "submit": submitted,
    }
    if tx_out:
        result["tx_out"] = str(Path(tx_out).expanduser())
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    print(_json_dumps(result))
    return 0



def _tier2_case(api: str, case_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/tier2/case/{urllib.parse.quote(case_id, safe='')}")


def _tier2_case_payload(api: str, case_id: str) -> Json:
    out = _tier2_case(api, case_id)
    case = out.get("case") if isinstance(out, dict) else None
    return case if isinstance(case, dict) else {}


def _tier2_case_id(*, account: str, nonce: int) -> str:
    return f"poh2:{str(account or '').strip()}:{max(0, int(nonce))}"


def _live_case(api: str, case_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/live/case/{urllib.parse.quote(case_id, safe='')}")


def _live_case_payload(api: str, case_id: str) -> Json:
    out = _live_case(api, case_id)
    case = out.get("case") if isinstance(out, dict) else None
    return case if isinstance(case, dict) else {}


def _live_session(api: str, session_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/live/session/{urllib.parse.quote(session_id, safe='')}")


def _live_session_payload(api: str, session_id: str) -> Json:
    out = _live_session(api, session_id)
    session = out.get("session") if isinstance(out, dict) else None
    return session if isinstance(session, dict) else {}


def _live_session_participants(api: str, session_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/live/session/{urllib.parse.quote(session_id, safe='')}/participants")


def _live_case_id(*, account: str, nonce: int) -> str:
    # Must mirror runtime apply_poh_live_request_open(), which creates
    # case ids via _case_id("poh_live", account_id=..., nonce=...).
    # Older rehearsal helpers derived legacy poh3:* ids, causing the
    # production-style Live request to submit successfully but then poll
    # a non-existent case.
    return f"poh_live:{str(account or '').strip()}:{max(0, int(nonce))}"


def _devnet_video_commitment(*, chain_id: str, account: str) -> str:
    material = "\n".join(
        [
            "weall-devnet-tier2-video-commitment-v1",
            str(chain_id or "").strip(),
            str(account or "").strip(),
            str(_now_ms()),
            "",
        ]
    ).encode("utf-8")
    return f"sha256:{_sha256_hex(material)}"


def cmd_tier2_request(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    account, priv, _pub, keydata = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)
    commitment = str(args.video_commitment or "").strip() or _devnet_video_commitment(
        chain_id=chain_id, account=account
    )
    skeleton = _http_json(
        "POST",
        args.api,
        "/v1/poh/tier2/tx/request",
        {"account_id": account, "target_tier": 2, "video_commitment": commitment},
    )
    tx_skel = skeleton.get("tx") if isinstance(skeleton, dict) else None
    if not isinstance(tx_skel, dict):
        raise SystemExit(f"Unexpected tier2 request skeleton response: {_json_dumps(skeleton)}")
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type="POH_TIER2_REQUEST_OPEN",
        signer=account,
        nonce=nonce,
        payload=tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else {"account_id": account, "target_tier": 2, "video_commitment": commitment},
        parent=args.parent,
        privkey=priv,
    )
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    case_id = _tier2_case_id(account=account, nonce=nonce)
    result: Json = {
        "ok": bool(submitted.get("ok", False)),
        "api": args.api,
        "chain_id": chain_id,
        "account": account,
        "case_id": case_id,
        "video_commitment": commitment,
        "tx_id": tx_id,
        "submit": submitted,
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["case"] = _tier2_case_payload(args.api, case_id)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_tier2_request_tx_id"] = tx_id
    keydata["last_poh_tier2_case_id"] = case_id
    keydata["last_poh_tier2_video_commitment"] = commitment
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    print(_json_dumps(result))
    return 0


def _sign_and_submit_skeleton_tx(
    *,
    api: str,
    chain_id: str,
    keyfile: Path,
    account: str,
    priv: str,
    route: str,
    request_body: Json,
    fallback_tx_type: str,
    fallback_payload: Json,
    parent: str | None,
    timeout: float,
    poll: float,
) -> Json:
    skeleton = _http_json("POST", api, route, request_body)
    tx_skel = skeleton.get("tx") if isinstance(skeleton, dict) else None
    if not isinstance(tx_skel, dict):
        raise SystemExit(f"Unexpected skeleton response from {route}: {_json_dumps(skeleton)}")
    nonce = _next_nonce(api, account)
    tx_type = str(tx_skel.get("tx_type") or fallback_tx_type).strip() or fallback_tx_type
    payload = tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else fallback_payload
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type=tx_type,
        signer=account,
        nonce=nonce,
        payload=payload,
        parent=parent,
        privkey=priv,
    )
    submitted = _http_json("POST", api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    out: Json = {
        "ok": bool(submitted.get("ok", False)),
        "api": api,
        "chain_id": chain_id,
        "account": account,
        "tx_id": tx_id,
        "tx_type": tx_type,
        "submit": submitted,
    }
    if tx_id:
        out["tx_status"] = _wait_tx(api, tx_id, timeout_s=timeout, poll_s=poll)
    return out


def cmd_live_request(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    account, priv, _pub, keydata = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)

    body: Json = {"account_id": account}
    for key, value in (
        ("session_commitment", args.session_commitment),
        ("room_commitment", args.room_commitment),
        ("prompt_commitment", args.prompt_commitment),
        ("device_pairing_commitment", args.device_pairing_commitment),
    ):
        v = str(value or "").strip()
        if v:
            body[key] = v

    skeleton = _http_json("POST", args.api, "/v1/poh/live/tx/request", body)
    tx_skel = skeleton.get("tx") if isinstance(skeleton, dict) else None
    if not isinstance(tx_skel, dict):
        raise SystemExit(f"Unexpected live request skeleton response: {_json_dumps(skeleton)}")
    payload = tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else body
    tx_type = str(tx_skel.get("tx_type") or "POH_LIVE_REQUEST_OPEN").strip() or "POH_LIVE_REQUEST_OPEN"

    tx = _sign_tx(
        chain_id=chain_id,
        tx_type=tx_type,
        signer=account,
        nonce=nonce,
        payload=payload,
        parent=args.parent,
        privkey=priv,
    )
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    case_id = _live_case_id(account=account, nonce=nonce)
    result: Json = {
        "ok": bool(submitted.get("ok", False)),
        "api": args.api,
        "chain_id": chain_id,
        "account": account,
        "case_id": case_id,
        "tx_id": tx_id,
        "tx_type": tx_type,
        "submit": submitted,
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["case"] = _live_case_payload(args.api, case_id)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_live_request_tx_id"] = tx_id
    keydata["last_poh_live_case_id"] = case_id
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    print(_json_dumps(result))
    return 0


def cmd_tier2_review(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    juror, priv, _pub, keydata = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    case_id = str(args.case_id or "").strip() or str(keydata.get("last_poh_tier2_case_id") or "").strip()
    if not case_id:
        raise SystemExit("missing --case-id")
    verdict = str(args.verdict or "").strip().lower()
    if verdict not in {"pass", "fail"}:
        raise SystemExit("--verdict must be pass or fail")

    result: Json = {"ok": True, "api": args.api, "chain_id": chain_id, "juror": juror, "case_id": case_id}
    if args.accept:
        accept = _sign_and_submit_skeleton_tx(
            api=args.api,
            chain_id=chain_id,
            keyfile=keyfile,
            account=juror,
            priv=priv,
            route="/v1/poh/tier2/tx/juror-accept",
            request_body={"case_id": case_id},
            fallback_tx_type="POH_TIER2_JUROR_ACCEPT",
            fallback_payload={"case_id": case_id},
            parent=args.parent,
            timeout=args.timeout,
            poll=args.poll,
        )
        result["accept"] = accept
        if str((accept.get("tx_status") or {}).get("status") or "").lower() != "confirmed":
            result["ok"] = False
            print(_json_dumps(result))
            return 2

    review = _sign_and_submit_skeleton_tx(
        api=args.api,
        chain_id=chain_id,
        keyfile=keyfile,
        account=juror,
        priv=priv,
        route="/v1/poh/tier2/tx/review",
        request_body={"case_id": case_id, "verdict": verdict},
        fallback_tx_type="POH_TIER2_REVIEW_SUBMIT",
        fallback_payload={"case_id": case_id, "verdict": verdict, "ts_ms": 0},
        parent=args.parent,
        timeout=args.timeout,
        poll=args.poll,
    )
    result["review"] = review
    result["case"] = _tier2_case_payload(args.api, case_id)
    keydata["last_poh_tier2_review_tx_id"] = str(review.get("tx_id") or "")
    keydata["last_poh_tier2_case_id"] = case_id
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    if str((review.get("tx_status") or {}).get("status") or "").lower() != "confirmed":
        result["ok"] = False
        print(_json_dumps(result))
        return 2
    print(_json_dumps(result))
    return 0


def cmd_live_review(args: argparse.Namespace) -> int:
    """Accept, attend, and optionally verdict a Live live verification case.

    This is a controlled-devnet harness over normal public tx skeleton routes.
    It signs each reviewer action with the juror key and submits through
    /v1/tx/submit; it never calls operator or demo-only mutation routes.
    """

    keyfile = Path(args.keyfile).expanduser()
    juror, priv, _pub, keydata = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    case_id = str(args.case_id or "").strip() or str(keydata.get("last_poh_live_case_id") or "").strip()
    if not case_id:
        raise SystemExit("missing --case-id")

    verdict = str(args.verdict or "").strip().lower()
    if verdict and verdict not in {"pass", "fail"}:
        raise SystemExit("--verdict must be pass, fail, or empty with --no-verdict")

    result: Json = {
        "ok": True,
        "api": args.api,
        "chain_id": chain_id,
        "juror": juror,
        "case_id": case_id,
    }

    if args.accept:
        accept = _sign_and_submit_skeleton_tx(
            api=args.api,
            chain_id=chain_id,
            keyfile=keyfile,
            account=juror,
            priv=priv,
            route="/v1/poh/live/tx/juror-accept",
            request_body={"case_id": case_id},
            fallback_tx_type="POH_LIVE_JUROR_ACCEPT",
            fallback_payload={"case_id": case_id},
            parent=args.parent,
            timeout=args.timeout,
            poll=args.poll,
        )
        result["accept"] = accept
        if str((accept.get("tx_status") or {}).get("status") or "").lower() != "confirmed":
            result["ok"] = False
            print(_json_dumps(result))
            return 2

    if args.attendance:
        attendance = _sign_and_submit_skeleton_tx(
            api=args.api,
            chain_id=chain_id,
            keyfile=keyfile,
            account=juror,
            priv=priv,
            route="/v1/poh/live/tx/attendance",
            request_body={"case_id": case_id, "juror_id": juror, "attended": True},
            fallback_tx_type="POH_LIVE_ATTENDANCE_MARK",
            fallback_payload={"case_id": case_id, "juror_id": juror, "attended": True, "ts_ms": 0},
            parent=args.parent,
            timeout=args.timeout,
            poll=args.poll,
        )
        result["attendance"] = attendance
        if str((attendance.get("tx_status") or {}).get("status") or "").lower() != "confirmed":
            result["ok"] = False
            print(_json_dumps(result))
            return 2

    if args.submit_verdict and verdict:
        review = _sign_and_submit_skeleton_tx(
            api=args.api,
            chain_id=chain_id,
            keyfile=keyfile,
            account=juror,
            priv=priv,
            route="/v1/poh/live/tx/verdict",
            request_body={"case_id": case_id, "verdict": verdict},
            fallback_tx_type="POH_LIVE_VERDICT_SUBMIT",
            fallback_payload={"case_id": case_id, "verdict": verdict, "ts_ms": 0},
            parent=args.parent,
            timeout=args.timeout,
            poll=args.poll,
        )
        result["verdict"] = review
        if str((review.get("tx_status") or {}).get("status") or "").lower() != "confirmed":
            result["ok"] = False
            print(_json_dumps(result))
            return 2

    case_payload = _live_case_payload(args.api, case_id)
    result["case"] = case_payload
    session_id = str(case_payload.get("session_id") or "").strip() or f"session:{case_id}"
    try:
        result["session"] = _live_session_payload(args.api, session_id)
    except SystemExit:
        result["session"] = {}
    try:
        result["participants"] = _live_session_participants(args.api, session_id).get("participants", [])
    except SystemExit:
        result["participants"] = []

    keydata["last_poh_live_review_tx_id"] = str(((result.get("verdict") or {}) if isinstance(result.get("verdict"), dict) else {}).get("tx_id") or "")
    keydata["last_poh_live_case_id"] = case_id
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    print(_json_dumps(result))
    return 0


def cmd_live_session(args: argparse.Namespace) -> int:
    print(_json_dumps(_live_session(args.api, args.session_id)))
    return 0


def cmd_live_participants(args: argparse.Namespace) -> int:
    print(_json_dumps(_live_session_participants(args.api, args.session_id)))
    return 0


def cmd_bootstrap_live(args: argparse.Namespace) -> int:
    """Submit a bounded open-bootstrap POH_BOOTSTRAP_TIER2_GRANT tx.

    This command is intended for controlled devnet reviewer preparation only.
    It uses the normal public tx submission path and succeeds only while the
    consensus-visible bootstrap policy is open and height-bounded.
    """

    keyfile = Path(args.keyfile).expanduser()
    account, priv, pub, keydata = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)
    payload: Json = {"account_id": account}
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer=account,
        nonce=nonce,
        payload=payload,
        parent=args.parent,
        privkey=priv,
    )
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    result: Json = {
        "ok": bool(submitted.get("ok", False)),
        "api": args.api,
        "chain_id": chain_id,
        "account": account,
        "tx_id": tx_id,
        "tx_type": "POH_BOOTSTRAP_TIER2_GRANT",
        "submit": submitted,
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_bootstrap_live_tx_id"] = tx_id
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    print(_json_dumps(result))
    return 0


def cmd_tier2_case(args: argparse.Namespace) -> int:
    print(_json_dumps(_tier2_case(args.api, args.case_id)))
    return 0


def cmd_tick(args: argparse.Namespace) -> int:
    keyfile = Path(args.keyfile).expanduser()
    account, priv, _pub, _data = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    payload = {"bio": f"devnet tick {args.label} {_now_ms()}"}
    nonce = _next_nonce(args.api, account)
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type="PROFILE_UPDATE",
        signer=account,
        nonce=nonce,
        payload=payload,
        parent=None,
        privkey=priv,
    )
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    result: Json = {"ok": bool(submitted.get("ok", False)), "api": args.api, "chain_id": chain_id, "account": account, "tx_id": tx_id, "submit": submitted}
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    print(_json_dumps(result))
    return 0

def cmd_wait_tx(args: argparse.Namespace) -> int:
    print(_json_dumps(_wait_tx(args.api, args.tx_id, timeout_s=args.timeout, poll_s=args.poll)))
    return 0


def cmd_account(args: argparse.Namespace) -> int:
    print(_json_dumps({"ok": True, "api": args.api, "account": args.account, "state": _account_state(args.api, args.account)}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Controlled-devnet transaction helper")
    p.add_argument("--api", default=os.environ.get("WEALL_API", "http://127.0.0.1:8001"), help="Node API base URL")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create-account", help="Generate/load a keypair and submit ACCOUNT_REGISTER")
    c.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    c.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    c.add_argument("--nonce", type=int, default=None)
    c.add_argument("--parent", default=None)
    c.add_argument(
        "--fresh",
        action="store_true",
        default=os.environ.get("WEALL_DEVNET_FRESH_ACCOUNT", "1").strip().lower()
        not in {"0", "false", "no", "off"},
        help="overwrite/create a fresh keyfile before registering; enabled by default for e2e smoke truthfulness",
    )
    c.add_argument(
        "--reuse-keyfile",
        dest="fresh",
        action="store_false",
        help="reuse existing keyfile instead of forcing a fresh account",
    )
    c.add_argument("--wait", action="store_true", default=True)
    c.add_argument("--no-wait", dest="wait", action="store_false")
    c.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    c.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    c.set_defaults(func=cmd_create_account)

    s = sub.add_parser("submit-tx", help="Sign and submit an arbitrary user tx")
    s.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    s.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    s.add_argument("--tx-type", required=True)
    s.add_argument("--payload-json", required=True, help="JSON object string or @path")
    s.add_argument("--nonce", type=int, default=None)
    s.add_argument("--parent", default=None)
    s.add_argument("--tx-out", default="", help="optional path to write the signed tx envelope before submission")
    s.add_argument("--wait", action="store_true")
    s.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    s.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    s.set_defaults(func=cmd_submit_tx)

    k = sub.add_parser("ensure-keyfile", help="Generate/load a devnet ed25519 keyfile without submitting txs")
    k.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    k.add_argument("--keyfile", required=True)
    k.add_argument("--print-private", action="store_true")
    k.set_defaults(func=cmd_ensure_keyfile)



    t2 = sub.add_parser("tier2-request", help="Submit a POH_TIER2_REQUEST_OPEN tx")
    t2.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    t2.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    t2.add_argument("--video-commitment", default=os.environ.get("WEALL_POH_TIER2_VIDEO_COMMITMENT", ""))
    t2.add_argument("--nonce", type=int, default=None)
    t2.add_argument("--parent", default=None)
    t2.add_argument("--wait", action="store_true", default=True)
    t2.add_argument("--no-wait", dest="wait", action="store_false")
    t2.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    t2.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    t2.set_defaults(func=cmd_tier2_request)

    r2 = sub.add_parser("tier2-review", help="Accept and submit a Tier-2 juror review")
    r2.add_argument("--account", default=os.environ.get("WEALL_TIER2_JUROR_ACCOUNT", os.environ.get("WEALL_BOOTSTRAP_OPERATOR_ACCOUNT", os.environ.get("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@devnet-genesis"))))
    r2.add_argument("--keyfile", default=os.environ.get("WEALL_TIER2_JUROR_KEYFILE", os.environ.get("WEALL_GENESIS_OPERATOR_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "genesis-operator.json"))))
    r2.add_argument("--case-id", default=os.environ.get("WEALL_TIER2_CASE_ID", ""))
    r2.add_argument("--verdict", default=os.environ.get("WEALL_TIER2_VERDICT", "pass"))
    r2.add_argument("--accept", action="store_true", default=True)
    r2.add_argument("--no-accept", dest="accept", action="store_false")
    r2.add_argument("--parent", default=None)
    r2.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    r2.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    r2.set_defaults(func=cmd_tier2_review)

    c2 = sub.add_parser("tier2-case", help="Read a Tier-2 PoH case")
    c2.add_argument("case_id")
    c2.set_defaults(func=cmd_tier2_case)

    b3 = sub.add_parser("bootstrap-live", help="Submit bounded devnet POH_BOOTSTRAP_TIER2_GRANT")
    b3.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    b3.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    b3.add_argument("--nonce", type=int, default=None)
    b3.add_argument("--parent", default=None)
    b3.add_argument("--wait", action="store_true", default=True)
    b3.add_argument("--no-wait", dest="wait", action="store_false")
    b3.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    b3.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    b3.set_defaults(func=cmd_bootstrap_live)

    t3 = sub.add_parser("live-request", help="Submit a dedicated POH_LIVE_REQUEST_OPEN tx")
    t3.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    t3.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    t3.add_argument("--session-commitment", default=os.environ.get("WEALL_POH_LIVE_SESSION_COMMITMENT", ""))
    t3.add_argument("--room-commitment", default=os.environ.get("WEALL_POH_LIVE_ROOM_COMMITMENT", ""))
    t3.add_argument("--prompt-commitment", default=os.environ.get("WEALL_POH_LIVE_PROMPT_COMMITMENT", ""))
    t3.add_argument("--device-pairing-commitment", default=os.environ.get("WEALL_POH_LIVE_DEVICE_PAIRING_COMMITMENT", ""))
    t3.add_argument("--nonce", type=int, default=None)
    t3.add_argument("--parent", default=None)
    t3.add_argument("--wait", action="store_true", default=True)
    t3.add_argument("--no-wait", dest="wait", action="store_false")
    t3.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    t3.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    t3.set_defaults(func=cmd_live_request)

    c3 = sub.add_parser("live-case", help="Read a Live PoH case")
    c3.add_argument("case_id")
    c3.set_defaults(func=lambda args: (print(_json_dumps(_live_case(args.api, args.case_id))) or 0))

    s3 = sub.add_parser("live-session", help="Read a Live live session")
    s3.add_argument("session_id")
    s3.set_defaults(func=cmd_live_session)

    p3 = sub.add_parser("live-participants", help="Read Live live session participants")
    p3.add_argument("session_id")
    p3.set_defaults(func=cmd_live_participants)

    r3 = sub.add_parser("live-review", help="Accept, attend, and optionally verdict a Live case")
    r3.add_argument("--account", default=os.environ.get("WEALL_LIVE_JUROR_ACCOUNT", os.environ.get("WEALL_ACCOUNT", "")))
    r3.add_argument("--keyfile", default=os.environ.get("WEALL_LIVE_JUROR_KEYFILE", os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "live-juror.json"))))
    r3.add_argument("--case-id", default=os.environ.get("WEALL_LIVE_CASE_ID", ""))
    r3.add_argument("--verdict", default=os.environ.get("WEALL_LIVE_VERDICT", "pass"))
    r3.add_argument("--accept", action="store_true", default=True)
    r3.add_argument("--no-accept", dest="accept", action="store_false")
    r3.add_argument("--attendance", action="store_true", default=True)
    r3.add_argument("--no-attendance", dest="attendance", action="store_false")
    r3.add_argument("--submit-verdict", action="store_true", default=True)
    r3.add_argument("--no-verdict", dest="submit_verdict", action="store_false")
    r3.add_argument("--parent", default=None)
    r3.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    r3.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    r3.set_defaults(func=cmd_live_review)

    tick = sub.add_parser("tick", help="Submit a harmless PROFILE_UPDATE to advance block/system queues")
    tick.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    tick.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    tick.add_argument("--label", default=os.environ.get("WEALL_DEVNET_TICK_LABEL", "tick"))
    tick.add_argument("--wait", action="store_true", default=True)
    tick.add_argument("--no-wait", dest="wait", action="store_false")
    tick.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    tick.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    tick.set_defaults(func=cmd_tick)

    w = sub.add_parser("wait-tx", help="Poll /v1/tx/status/{tx_id}")
    w.add_argument("tx_id")
    w.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    w.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    w.set_defaults(func=cmd_wait_tx)

    a = sub.add_parser("account", help="Read canonical account state")
    a.add_argument("account")
    a.set_defaults(func=cmd_account)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
