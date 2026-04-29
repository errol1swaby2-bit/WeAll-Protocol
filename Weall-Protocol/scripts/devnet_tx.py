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

def cmd_email_tier1(args: argparse.Namespace) -> int:
    """Submit a Tier-1 email-control attestation through normal public APIs.

    Controlled devnet uses the WeAll-hosted oracle/API flow: begin challenge,
    complete challenge, receive a provider-neutral email_control_attestation_v1,
    sign POH_EMAIL_ATTESTATION_SUBMIT with the subject account key, and submit
    the tx through /v1/tx/submit.
    """

    subject_keyfile = Path(args.keyfile).expanduser()
    account, priv, _pub, keydata = _key_material(subject_keyfile, account=args.account)
    chain_id = _chain_id(args.api)

    begin = _http_json(
        "POST",
        args.api,
        "/v1/poh/email/begin",
        {"account": account, "email": args.email},
    )
    request_id = str(begin.get("request_id") or begin.get("challenge_id") or args.request_id or "").strip()
    if not request_id:
        raise SystemExit(f"Unexpected email begin response: {_json_dumps(begin)}")

    code = str(args.code or begin.get("dev_code") or "").strip()
    if not code:
        raise SystemExit(
            "missing email verification code; set WEALL_POH_EMAIL_EXPOSE_DEV_CODE=1 on the devnet API "
            "or pass --code/WEALL_EMAIL_CODE"
        )

    completed = _http_json(
        "POST",
        args.api,
        "/v1/poh/email/complete",
        {"account": account, "email": args.email, "request_id": request_id, "code": code},
    )
    tx_skel = completed.get("tx") if isinstance(completed, dict) else None
    if not isinstance(tx_skel, dict):
        attestation = completed.get("attestation") if isinstance(completed, dict) else None
        if not isinstance(attestation, dict):
            raise SystemExit(f"Unexpected email complete response: {_json_dumps(completed)}")
        tx_skel = {
            "tx_type": "POH_EMAIL_ATTESTATION_SUBMIT",
            "payload": {"account_id": account, "attestation": attestation},
            "parent": None,
        }

    tx_type = str(tx_skel.get("tx_type") or "POH_EMAIL_ATTESTATION_SUBMIT").strip().upper()
    if tx_type != "POH_EMAIL_ATTESTATION_SUBMIT":
        raise SystemExit(f"unsupported email Tier-1 tx_type from oracle: {tx_type}")

    if args.attestation_out:
        out_path = Path(args.attestation_out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_json_dumps(completed.get("attestation") or tx_skel.get("payload") or {}) + "\n", encoding="utf-8")

    nonce = int(args.nonce) if args.nonce is not None else _next_nonce(args.api, account)
    tx = _sign_tx(
        chain_id=chain_id,
        tx_type="POH_EMAIL_ATTESTATION_SUBMIT",
        signer=account,
        nonce=nonce,
        payload=tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else {},
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
        "request_id": request_id,
        "tx_type": "POH_EMAIL_ATTESTATION_SUBMIT",
        "tx_id": tx_id,
        "submit": submitted,
        "security_phrase": str(begin.get("security_phrase") or completed.get("security_phrase") or ""),
        "official_sender": str(begin.get("official_sender") or ""),
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_email_attestation_tx_id"] = tx_id
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


def _tier3_case(api: str, case_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/tier3/case/{urllib.parse.quote(case_id, safe='')}")


def _tier3_case_payload(api: str, case_id: str) -> Json:
    out = _tier3_case(api, case_id)
    case = out.get("case") if isinstance(out, dict) else None
    return case if isinstance(case, dict) else {}


def _tier3_session(api: str, session_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/tier3/session/{urllib.parse.quote(session_id, safe='')}")


def _tier3_session_payload(api: str, session_id: str) -> Json:
    out = _tier3_session(api, session_id)
    session = out.get("session") if isinstance(out, dict) else None
    return session if isinstance(session, dict) else {}


def _tier3_session_participants(api: str, session_id: str) -> Json:
    return _http_json("GET", api, f"/v1/poh/tier3/session/{urllib.parse.quote(session_id, safe='')}/participants")


def _tier3_case_id(*, account: str, nonce: int) -> str:
    return f"poh3:{str(account or '').strip()}:{max(0, int(nonce))}"


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


def cmd_tier3_request(args: argparse.Namespace) -> int:
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

    skeleton = _http_json("POST", args.api, "/v1/poh/tier3/tx/request", body)
    tx_skel = skeleton.get("tx") if isinstance(skeleton, dict) else None
    if not isinstance(tx_skel, dict):
        raise SystemExit(f"Unexpected tier3 request skeleton response: {_json_dumps(skeleton)}")
    payload = tx_skel.get("payload") if isinstance(tx_skel.get("payload"), dict) else body
    tx_type = str(tx_skel.get("tx_type") or "POH_TIER3_REQUEST_OPEN").strip() or "POH_TIER3_REQUEST_OPEN"

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
    case_id = _tier3_case_id(account=account, nonce=nonce)
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
        result["case"] = _tier3_case_payload(args.api, case_id)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_tier3_request_tx_id"] = tx_id
    keydata["last_poh_tier3_case_id"] = case_id
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


def cmd_tier3_review(args: argparse.Namespace) -> int:
    """Accept, attend, and optionally verdict a Tier-3 live verification case.

    This is a controlled-devnet harness over normal public tx skeleton routes.
    It signs each reviewer action with the juror key and submits through
    /v1/tx/submit; it never calls operator or demo-only mutation routes.
    """

    keyfile = Path(args.keyfile).expanduser()
    juror, priv, _pub, keydata = _key_material(keyfile, account=args.account)
    chain_id = _chain_id(args.api)
    case_id = str(args.case_id or "").strip() or str(keydata.get("last_poh_tier3_case_id") or "").strip()
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
            route="/v1/poh/tier3/tx/juror-accept",
            request_body={"case_id": case_id},
            fallback_tx_type="POH_TIER3_JUROR_ACCEPT",
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
            route="/v1/poh/tier3/tx/attendance",
            request_body={"case_id": case_id, "juror_id": juror, "attended": True},
            fallback_tx_type="POH_TIER3_ATTENDANCE_MARK",
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
            route="/v1/poh/tier3/tx/verdict",
            request_body={"case_id": case_id, "verdict": verdict},
            fallback_tx_type="POH_TIER3_VERDICT_SUBMIT",
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

    case_payload = _tier3_case_payload(args.api, case_id)
    result["case"] = case_payload
    session_id = str(case_payload.get("session_id") or "").strip() or f"session:{case_id}"
    try:
        result["session"] = _tier3_session_payload(args.api, session_id)
    except SystemExit:
        result["session"] = {}
    try:
        result["participants"] = _tier3_session_participants(args.api, session_id).get("participants", [])
    except SystemExit:
        result["participants"] = []

    keydata["last_poh_tier3_review_tx_id"] = str(((result.get("verdict") or {}) if isinstance(result.get("verdict"), dict) else {}).get("tx_id") or "")
    keydata["last_poh_tier3_case_id"] = case_id
    keyfile.write_text(_json_dumps(keydata) + "\n", encoding="utf-8")
    print(_json_dumps(result))
    return 0


def cmd_tier3_session(args: argparse.Namespace) -> int:
    print(_json_dumps(_tier3_session(args.api, args.session_id)))
    return 0


def cmd_tier3_participants(args: argparse.Namespace) -> int:
    print(_json_dumps(_tier3_session_participants(args.api, args.session_id)))
    return 0


def cmd_bootstrap_tier3(args: argparse.Namespace) -> int:
    """Submit a bounded open-bootstrap POH_BOOTSTRAP_TIER3_GRANT tx.

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
        tx_type="POH_BOOTSTRAP_TIER3_GRANT",
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
        "tx_type": "POH_BOOTSTRAP_TIER3_GRANT",
        "submit": submitted,
    }
    if args.wait and tx_id:
        result["tx_status"] = _wait_tx(args.api, tx_id, timeout_s=args.timeout, poll_s=args.poll)
        result["account_state"] = _account_state(args.api, account)
    keydata["last_poh_bootstrap_tier3_tx_id"] = tx_id
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

    e = sub.add_parser("email-tier1", help="Submit a chain-bound POH_EMAIL_ATTESTATION_SUBMIT tx")
    e.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    e.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    e.add_argument("--email", required=True)
    e.add_argument("--request-id", default=os.environ.get("WEALL_EMAIL_REQUEST_ID", ""))
    e.add_argument("--code", default=os.environ.get("WEALL_EMAIL_CODE", ""))
    e.add_argument("--attestation-out", default="")
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

    b3 = sub.add_parser("bootstrap-tier3", help="Submit bounded devnet POH_BOOTSTRAP_TIER3_GRANT")
    b3.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    b3.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    b3.add_argument("--nonce", type=int, default=None)
    b3.add_argument("--parent", default=None)
    b3.add_argument("--wait", action="store_true", default=True)
    b3.add_argument("--no-wait", dest="wait", action="store_false")
    b3.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    b3.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    b3.set_defaults(func=cmd_bootstrap_tier3)

    t3 = sub.add_parser("tier3-request", help="Submit a dedicated POH_TIER3_REQUEST_OPEN tx")
    t3.add_argument("--account", default=os.environ.get("WEALL_ACCOUNT", ""))
    t3.add_argument("--keyfile", default=os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "devnet-account.json")))
    t3.add_argument("--session-commitment", default=os.environ.get("WEALL_POH_TIER3_SESSION_COMMITMENT", ""))
    t3.add_argument("--room-commitment", default=os.environ.get("WEALL_POH_TIER3_ROOM_COMMITMENT", ""))
    t3.add_argument("--prompt-commitment", default=os.environ.get("WEALL_POH_TIER3_PROMPT_COMMITMENT", ""))
    t3.add_argument("--device-pairing-commitment", default=os.environ.get("WEALL_POH_TIER3_DEVICE_PAIRING_COMMITMENT", ""))
    t3.add_argument("--nonce", type=int, default=None)
    t3.add_argument("--parent", default=None)
    t3.add_argument("--wait", action="store_true", default=True)
    t3.add_argument("--no-wait", dest="wait", action="store_false")
    t3.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    t3.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    t3.set_defaults(func=cmd_tier3_request)

    c3 = sub.add_parser("tier3-case", help="Read a Tier-3 PoH case")
    c3.add_argument("case_id")
    c3.set_defaults(func=lambda args: (print(_json_dumps(_tier3_case(args.api, args.case_id))) or 0))

    s3 = sub.add_parser("tier3-session", help="Read a Tier-3 live session")
    s3.add_argument("session_id")
    s3.set_defaults(func=cmd_tier3_session)

    p3 = sub.add_parser("tier3-participants", help="Read Tier-3 live session participants")
    p3.add_argument("session_id")
    p3.set_defaults(func=cmd_tier3_participants)

    r3 = sub.add_parser("tier3-review", help="Accept, attend, and optionally verdict a Tier-3 case")
    r3.add_argument("--account", default=os.environ.get("WEALL_TIER3_JUROR_ACCOUNT", os.environ.get("WEALL_ACCOUNT", "")))
    r3.add_argument("--keyfile", default=os.environ.get("WEALL_TIER3_JUROR_KEYFILE", os.environ.get("WEALL_KEYFILE", str(REPO_ROOT / ".weall-devnet" / "accounts" / "tier3-juror.json"))))
    r3.add_argument("--case-id", default=os.environ.get("WEALL_TIER3_CASE_ID", ""))
    r3.add_argument("--verdict", default=os.environ.get("WEALL_TIER3_VERDICT", "pass"))
    r3.add_argument("--accept", action="store_true", default=True)
    r3.add_argument("--no-accept", dest="accept", action="store_false")
    r3.add_argument("--attendance", action="store_true", default=True)
    r3.add_argument("--no-attendance", dest="attendance", action="store_false")
    r3.add_argument("--submit-verdict", action="store_true", default=True)
    r3.add_argument("--no-verdict", dest="submit_verdict", action="store_false")
    r3.add_argument("--parent", default=None)
    r3.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    r3.add_argument("--poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    r3.set_defaults(func=cmd_tier3_review)

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
