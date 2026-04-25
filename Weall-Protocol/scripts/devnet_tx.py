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
from weall.poh.operator_email_receipts import (  # noqa: E402
    RECEIPT_KIND,
    RECEIPT_VERSION,
    RELAY_TOKEN_KIND,
    RELAY_TOKEN_VERSION,
    canonical_receipt_message,
    canonical_relay_token_message,
)

Json = dict[str, Any]


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_email_for_commitment(email: str) -> str:
    return str(email or "").strip().lower()


def _email_commitment(*, chain_id: str, email: str) -> str:
    """Return the chain-bound opaque email commitment used by devnet Tier-1 receipts.

    The plaintext address never appears in the tx payload. The commitment is
    intentionally chain-bound so a devnet receipt cannot be replayed across
    independent chains that happen to share operator keys.
    """

    material = "\n".join(
        [
            "weall-devnet-email-commitment-v1",
            str(chain_id or "").strip(),
            _normalize_email_for_commitment(email),
            "",
        ]
    ).encode("utf-8")
    return f"sha256:{_sha256_hex(material)}"



def _load_json_arg(raw: str) -> Json:
    text = str(raw or "").strip()
    if not text:
        return {}
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _http_json(method: str, api: str, path: str, body: Any | None = None, timeout: float = 15.0) -> Json:
    base = str(api or "").rstrip("/")
    url = base + path
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {"ok": True}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(raw)
        except Exception:
            detail = {"raw": raw}
        raise SystemExit(f"HTTP {exc.code} {method} {url}\n{_json_dumps(detail)}") from exc


def _quote_account(account: str) -> str:
    return urllib.parse.quote(str(account or "").strip(), safe="")


def _chain_identity(api: str) -> Json:
    return _http_json("GET", api, "/v1/chain/identity")


def _chain_id(api: str) -> str:
    ident = _chain_identity(api)
    chain_id = str(ident.get("chain_id") or "").strip()
    if not chain_id:
        raise SystemExit("Node did not expose a chain_id at /v1/chain/identity")
    return chain_id


def _account_state(api: str, account: str) -> Json:
    out = _http_json("GET", api, f"/v1/accounts/{_quote_account(account)}")
    state = out.get("state") if isinstance(out, dict) else None
    return state if isinstance(state, dict) else {}


def _next_nonce(api: str, account: str) -> int:
    st = _account_state(api, account)
    try:
        return int(st.get("nonce") or 0) + 1
    except Exception:
        return 1


def _wait_tx(api: str, tx_id: str, *, timeout_s: float, poll_s: float) -> Json:
    deadline = time.time() + float(timeout_s)
    last: Json = {"ok": False, "status": "not_checked"}
    while time.time() <= deadline:
        last = _http_json("GET", api, f"/v1/tx/status/{urllib.parse.quote(tx_id, safe='')}")
        status = str(last.get("status") or "").strip().lower()
        if status in {"confirmed", "committed", "applied"}:
            return last
        time.sleep(float(poll_s))
    return last


def _generate_keypair() -> tuple[str, str]:
    sk = SigningKey.generate()
    return sk.encode().hex(), sk.verify_key.encode().hex()


def _load_or_create_keyfile(path: Path, *, account: str | None, fresh: bool = False) -> Json:
    if path.exists() and not fresh:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise SystemExit(f"Keyfile is not a JSON object: {path}")
        return data

    priv, pub = _generate_keypair()
    acct = str(account or "").strip() or f"@devnet_{int(time.time())}_{os.getpid()}"
    data = {"account": acct, "private_key_hex": priv, "public_key_hex": pub}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json_dumps(data) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass
    return data


def _key_material(path: Path, *, account: str | None = None, fresh: bool = False) -> tuple[str, str, str, Json]:
    data = _load_or_create_keyfile(path, account=account, fresh=fresh)
    acct = str(account or data.get("account") or "").strip()
    priv = str(data.get("private_key_hex") or data.get("privkey") or "").strip()
    pub = str(data.get("public_key_hex") or data.get("pubkey") or "").strip()
    if not acct or not priv or not pub:
        raise SystemExit(f"Keyfile missing account/private_key_hex/public_key_hex: {path}")
    data["account"] = acct
    data["private_key_hex"] = priv
    data["public_key_hex"] = pub
    return acct, priv, pub, data


def _sign_tx(*, chain_id: str, tx_type: str, signer: str, nonce: int, payload: Json, privkey: str, parent: str | None = None) -> Json:
    tx: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": int(nonce),
        "payload": payload,
        "sig": "",
        "parent": parent,
        "system": False,
        "chain_id": chain_id,
    }
    return sign_tx_envelope_dict(tx=tx, privkey=privkey)


def _sign_detached_hex(*, privkey_hex: str, message: bytes) -> str:
    try:
        sk = SigningKey(bytes.fromhex(str(privkey_hex or "").strip()))
    except Exception as exc:
        raise SystemExit("invalid private key hex") from exc
    return sk.sign(message).signature.hex()


def _make_relay_token(
    *,
    chain_id: str,
    challenge_id: str,
    subject_account_id: str,
    operator_account_id: str,
    email: str,
    relay_account_id: str,
    relay_pubkey: str,
    relay_privkey: str,
    ttl_ms: int,
) -> Json:
    now_ms = _now_ms()
    payload: Json = {
        "version": RELAY_TOKEN_VERSION,
        "type": RELAY_TOKEN_KIND,
        "chain_id": str(chain_id or "").strip(),
        "challenge_id": str(challenge_id or "").strip(),
        "account_id": str(subject_account_id or "").strip(),
        "operator_account_id": str(operator_account_id or "").strip(),
        "email_commitment": _email_commitment(chain_id=chain_id, email=email),
        "issued_at_ms": now_ms,
        "expires_at_ms": now_ms + int(ttl_ms),
        "relay_account_id": str(relay_account_id or "").strip(),
        "relay_pubkey": str(relay_pubkey or "").strip().lower(),
    }
    if not payload["chain_id"]:
        raise SystemExit("missing chain_id")
    if not payload["challenge_id"]:
        raise SystemExit("missing request_id/challenge_id")
    if not payload["account_id"]:
        raise SystemExit("missing subject account")
    if not payload["operator_account_id"]:
        raise SystemExit("missing operator account")
    if not payload["relay_account_id"] or not payload["relay_pubkey"]:
        raise SystemExit("missing relay account/pubkey")
    return {
        "payload": payload,
        "signature": _sign_detached_hex(
            privkey_hex=relay_privkey,
            message=canonical_relay_token_message(payload),
        ),
    }


def _make_operator_email_receipt(
    *,
    chain_id: str,
    subject_account_id: str,
    operator_account_id: str,
    operator_pubkey: str,
    operator_privkey: str,
    relay_token: Json,
) -> Json:
    relay_payload = relay_token.get("payload") if isinstance(relay_token, dict) else None
    if not isinstance(relay_payload, dict):
        raise SystemExit("relay token payload missing")
    receipt: Json = {
        "version": RECEIPT_VERSION,
        "kind": RECEIPT_KIND,
        "chain_id": str(chain_id or "").strip(),
        "worker_account_id": str(operator_account_id or "").strip(),
        "worker_pubkey": str(operator_pubkey or "").strip().lower(),
        "subject_account_id": str(subject_account_id or "").strip(),
        "email_commitment": str(relay_payload.get("email_commitment") or "").strip(),
        "request_id": str(relay_payload.get("challenge_id") or "").strip(),
        "nonce": str(relay_token.get("signature") or "").strip(),
        "issued_at_ms": int(relay_payload.get("issued_at_ms") or 0),
        "expires_at_ms": int(relay_payload.get("expires_at_ms") or 0),
        "relay_token": relay_token,
    }
    receipt["signature"] = _sign_detached_hex(
        privkey_hex=operator_privkey,
        message=canonical_receipt_message(receipt),
    )
    return receipt


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
    submitted = _http_json("POST", args.api, "/v1/tx/submit", tx)
    tx_id = str(submitted.get("tx_id") or "").strip()
    result: Json = {"ok": bool(submitted.get("ok", False)), "api": args.api, "chain_id": chain_id, "account": account, "tx_id": tx_id, "submit": submitted}
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    print(_json_dumps(result))
    return 0


def cmd_email_tier1(args: argparse.Namespace) -> int:
    """Build and submit a bounded Tier-1 email oracle receipt tx.

    This controlled-devnet harness produces a signed relay token and a signed
    operator receipt, then submits a normal POH_EMAIL_RECEIPT_SUBMIT tx through
    the public API. It never mutates local state directly and never calls demo
    seed routes.
    """

    subject_keyfile = Path(args.keyfile).expanduser()
    account, priv, _pub, keydata = _key_material(subject_keyfile, account=args.account)
    operator_account, operator_priv, operator_pub, _operator_data = _key_material(
        Path(args.operator_keyfile).expanduser(), account=args.operator_account
    )
    relay_account, relay_priv, relay_pub, _relay_data = _key_material(
        Path(args.relay_keyfile).expanduser(), account=args.relay_account
    )

    chain_id = _chain_id(args.api)
    request_id = str(args.request_id or "").strip()
    if not request_id:
        request_material = f"{chain_id}|{account}|{_normalize_email_for_commitment(args.email)}|{_now_ms()}".encode("utf-8")
        request_id = f"email:{_sha256_hex(request_material)[:32]}"

    ttl_ms = int(args.ttl_ms)
    if ttl_ms <= 0:
        raise SystemExit("--ttl-ms must be positive")

    relay_token = _make_relay_token(
        chain_id=chain_id,
        challenge_id=request_id,
        subject_account_id=account,
        operator_account_id=operator_account,
        email=args.email,
        relay_account_id=relay_account,
        relay_pubkey=relay_pub,
        relay_privkey=relay_priv,
        ttl_ms=ttl_ms,
    )
    receipt = _make_operator_email_receipt(
        chain_id=chain_id,
        subject_account_id=account,
        operator_account_id=operator_account,
        operator_pubkey=operator_pub,
        operator_privkey=operator_priv,
        relay_token=relay_token,
    )

    if args.receipt_out:
        out_path = Path(args.receipt_out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_json_dumps(receipt) + "\n", encoding="utf-8")

    skeleton = _http_json(
        "POST",
        args.api,
        "/v1/poh/email/tx/receipt-submit",
        {"account_id": account, "receipt": receipt},
    )
    tx_skel = skeleton.get("tx") if isinstance(skeleton, dict) else None
    if not isinstance(tx_skel, dict):
        raise SystemExit(f"Unexpected email receipt skeleton response: {_json_dumps(skeleton)}")

    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type="POH_EMAIL_RECEIPT_SUBMIT",
        signer=account,
        nonce=nonce,
        payload=tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else {"account_id": account, "receipt": receipt},
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
        "operator_account": operator_account,
        "relay_account": relay_account,
        "request_id": request_id,
        "email_commitment": receipt.get("email_commitment"),
        "tx_id": tx_id,
        "submit": submitted,
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_email_receipt_tx_id"] = tx_id
    keydata["last_poh_email_request_id"] = request_id
    keydata["chain_id"] = chain_id
    subject_keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
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
    s.add_argument("--wait", action="store_true")
    s.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    s.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    s.set_defaults(func=cmd_submit_tx)

    k = sub.add_parser("ensure-keyfile", help="Generate/load a devnet ed25519 keyfile without submitting txs")
    k.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    k.add_argument("--keyfile", required=True)
    k.add_argument("--print-private", action="store_true")
    k.set_defaults(func=cmd_ensure_keyfile)

    e = sub.add_parser("email-tier1", help="Submit a chain-bound POH_EMAIL_RECEIPT_SUBMIT tx")
    e.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    e.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    e.add_argument("--email", required=True)
    e.add_argument("--request-id", default=os.environ.get("WEALL_EMAIL_REQUEST_ID", ""))
    e.add_argument("--operator-account", default=os.environ.get("WEALL_ORACLE_OPERATOR_ACCOUNT", os.environ.get("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@devnet-genesis")))
    e.add_argument("--operator-keyfile", default=os.environ.get("WEALL_GENESIS_OPERATOR_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "genesis-operator.json")))
    e.add_argument("--relay-account", default=os.environ.get("WEALL_EMAIL_RELAY_ACCOUNT_ID", "@devnet-email-relay"))
    e.add_argument("--relay-keyfile", default=os.environ.get("WEALL_EMAIL_RELAY_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "email-relay.json")))
    e.add_argument("--ttl-ms", type=int, default=int(os.environ.get("WEALL_POH_EMAIL_TTL_MS", "900000")))
    e.add_argument("--receipt-out", default="")
    e.add_argument("--nonce", type=int, default=None)
    e.add_argument("--parent", default=None)
    e.add_argument("--wait", action="store_true", default=True)
    e.add_argument("--no-wait", dest="wait", action="store_false")
    e.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    e.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    e.set_defaults(func=cmd_email_tier1)


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
    r2.add_argument("--account", default=os.environ.get("WEALL_TIER2_JUROR_ACCOUNT", os.environ.get("WEALL_ORACLE_OPERATOR_ACCOUNT", os.environ.get("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@devnet-genesis"))))
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
