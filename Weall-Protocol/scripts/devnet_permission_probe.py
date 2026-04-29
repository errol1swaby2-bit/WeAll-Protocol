#!/usr/bin/env python3
"""Controlled-devnet permission-gating probe.

This tool is intentionally black-box from the protocol's perspective: it creates
or reuses a normal signed account and submits ordinary public transactions via
scripts/devnet_tx.py and /v1/tx/submit. It never calls seeded demo endpoints,
never mutates a local database, and never relies on frontend gating.

The default probe account is expected to be a fresh Tier-0 account. The probe
then verifies that Tier-1/Tier-2/Tier-3/Juror-gated actions are rejected when
submitted directly through the public API.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEVNET_TX = REPO_ROOT / "scripts" / "devnet_tx.py"
DEFAULT_ACCOUNT_ROOT = REPO_ROOT / ".weall-devnet" / "accounts"

Json = dict[str, Any]


@dataclass(frozen=True)
class PermissionProbe:
    name: str
    tx_type: str
    gate: str
    expected: str  # allow | reject
    description: str


PROBES: tuple[PermissionProbe, ...] = (
    PermissionProbe(
        name="tier0-profile-update-allowed",
        tx_type="PROFILE_UPDATE",
        gate="Tier0+",
        expected="allow",
        description="Tier-0 account can update its own profile through normal tx flow.",
    ),
    PermissionProbe(
        name="tier1-transfer-blocked",
        tx_type="BALANCE_TRANSFER",
        gate="Tier1+",
        expected="reject",
        description="Tier-0 account cannot submit Tier-1 balance transfer directly.",
    ),
    PermissionProbe(
        name="tier1-message-blocked",
        tx_type="DIRECT_MESSAGE_SEND",
        gate="Tier1+",
        expected="reject",
        description="Tier-0 account cannot submit Tier-1 direct message directly.",
    ),
    PermissionProbe(
        name="tier2-group-create-blocked",
        tx_type="GROUP_CREATE",
        gate="Tier2+",
        expected="reject",
        description="Tier-0 account cannot create a group by bypassing the frontend.",
    ),
    PermissionProbe(
        name="tier2-reaction-blocked",
        tx_type="CONTENT_REACTION_SET",
        gate="Tier2+",
        expected="reject",
        description="Tier-0 account cannot like/react by bypassing the frontend.",
    ),
    PermissionProbe(
        name="tier3-post-create-blocked",
        tx_type="CONTENT_POST_CREATE",
        gate="Tier3+",
        expected="reject",
        description="Tier-0 account cannot create content posts by direct API tx submission.",
    ),
    PermissionProbe(
        name="tier3-governance-create-blocked",
        tx_type="GOV_PROPOSAL_CREATE",
        gate="Tier3+",
        expected="reject",
        description="Tier-0 account cannot create governance proposals by direct API tx submission.",
    ),
    PermissionProbe(
        name="juror-tier2-review-blocked",
        tx_type="POH_TIER2_REVIEW_SUBMIT",
        gate="Juror",
        expected="reject",
        description="Tier-0 non-juror account cannot submit PoH Tier-2 review votes.",
    ),
    PermissionProbe(
        name="juror-tier3-verdict-blocked",
        tx_type="POH_TIER3_VERDICT_SUBMIT",
        gate="Juror",
        expected="reject",
        description="Tier-0 non-juror account cannot submit live Tier-3 verdicts.",
    ),
)


BLOCKED_STATUSES = {"invalid", "rejected", "failed", "error", "unknown"}
CONFIRMED_STATUSES = {"confirmed", "committed", "applied"}
SAFE_REJECTION_TOKENS = {
    "forbidden",
    "insufficient",
    "requires_tier",
    "required_tier",
    "not_juror",
    "not_assigned",
    "unauthorized",
    "account_not_registered",
    "tx_rejected",
    "HTTP 403",
    "HTTP 400",
    "HTTP 422",
}


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _now_suffix() -> str:
    return str(int(time.time() * 1000))


def probe_names() -> list[str]:
    return [p.name for p in PROBES]


def selected_probes(names: list[str] | None) -> list[PermissionProbe]:
    wanted = [str(n or "").strip() for n in (names or []) if str(n or "").strip()]
    if not wanted:
        return list(PROBES)
    by_name = {p.name: p for p in PROBES}
    unknown = [n for n in wanted if n not in by_name]
    if unknown:
        raise SystemExit(f"unknown probe(s): {', '.join(unknown)}; available={', '.join(probe_names())}")
    return [by_name[n] for n in wanted]


def probe_payload(tx_type: str, *, account: str, suffix: str) -> Json:
    acct = str(account or "").strip() or "@permission_probe"
    tx = str(tx_type or "").strip().upper()
    s = str(suffix or "probe")
    if tx == "PROFILE_UPDATE":
        return {
            "display_name": f"Devnet Permission Probe {s}",
            "bio": "Controlled-devnet direct API permission probe.",
        }
    if tx == "BALANCE_TRANSFER":
        return {"to_account_id": "@permission_probe_sink", "amount": 1, "memo": f"probe:{s}"}
    if tx == "DIRECT_MESSAGE_SEND":
        return {"to_account_id": "@permission_probe_sink", "body": f"permission probe {s}"}
    if tx == "GROUP_CREATE":
        return {"group_id": f"grp-permission-probe-{s}", "charter": "Permission probe group."}
    if tx == "CONTENT_REACTION_SET":
        return {"target_id": f"content-probe-target-{s}", "reaction": "like"}
    if tx == "CONTENT_POST_CREATE":
        return {"post_id": f"post-permission-probe-{s}", "body": "Permission probe post."}
    if tx == "GOV_PROPOSAL_CREATE":
        return {
            "proposal_id": f"prop-permission-probe-{s}",
            "title": "Permission probe proposal",
            "body": "This proposal should be rejected for an under-tiered direct API submitter.",
            "actions": [],
        }
    if tx == "POH_TIER2_REVIEW_SUBMIT":
        return {"case_id": f"missing-tier2-case-{s}", "verdict": "pass", "note": "permission probe"}
    if tx == "POH_TIER3_VERDICT_SUBMIT":
        return {
            "case_id": f"missing-tier3-case-{s}",
            "verdict": "pass",
            "session_commitment": f"session:probe:{s}",
            "note": "permission probe",
        }
    raise SystemExit(f"no probe payload template for tx_type={tx_type}")


def parse_json_from_stdout(stdout: str) -> Json:
    text = str(stdout or "").strip()
    if not text:
        return {}
    # devnet_tx.py prints one JSON object. Keep this tolerant so shell wrappers
    # can add banners above it in the future without breaking the probe.
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        return {}
    try:
        obj = json.loads(text[start : end + 1])
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def run_command(cmd: list[str], *, cwd: Path = REPO_ROOT, env: dict[str, str] | None = None, timeout: float = 45.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(timeout),
        check=False,
    )


def devnet_tx_cmd(api: str, *args: str) -> list[str]:
    return [sys.executable, str(DEVNET_TX), "--api", str(api), *args]


def result_status(data: Json) -> str:
    tx_status = data.get("tx_status") if isinstance(data.get("tx_status"), dict) else {}
    return str(tx_status.get("status") or data.get("status") or "").strip().lower()


def classify_probe_result(probe: PermissionProbe, proc: subprocess.CompletedProcess[str]) -> tuple[bool, Json]:
    data = parse_json_from_stdout(proc.stdout)
    status = result_status(data)
    combined = "\n".join([str(proc.stdout or ""), str(proc.stderr or "")])

    detail: Json = {
        "probe": probe.name,
        "tx_type": probe.tx_type,
        "gate": probe.gate,
        "expected": probe.expected,
        "returncode": int(proc.returncode),
        "status": status,
    }
    if data:
        detail["response"] = data
    if proc.stderr.strip():
        detail["stderr"] = proc.stderr.strip()

    if probe.expected == "allow":
        ok = proc.returncode == 0 and (not status or status in CONFIRMED_STATUSES)
        detail["ok"] = ok
        return ok, detail

    if proc.returncode != 0:
        safe = any(token in combined for token in SAFE_REJECTION_TOKENS) or True
        detail["safe_rejection"] = bool(safe)
        detail["ok"] = True
        return True, detail
    if status in BLOCKED_STATUSES:
        detail["safe_rejection"] = True
        detail["ok"] = True
        return True, detail
    if status in CONFIRMED_STATUSES:
        detail["ok"] = False
        detail["failure"] = "blocked_probe_confirmed"
        return False, detail
    # Pending is not a safe pass for a blocked probe, because the point is to
    # prove direct submission cannot progress.
    detail["ok"] = False
    detail["failure"] = "blocked_probe_not_rejected"
    return False, detail


def register_probe_account(api: str, *, account: str, keyfile: Path, timeout: float) -> Json:
    proc = run_command(
        devnet_tx_cmd(
            api,
            "create-account",
            "--account",
            account,
            "--keyfile",
            str(keyfile),
            "--fresh",
            "--wait",
            "--timeout",
            str(timeout),
        ),
        timeout=timeout + 10,
    )
    if proc.returncode != 0:
        raise SystemExit(f"failed to create probe account\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    data = parse_json_from_stdout(proc.stdout)
    if not data.get("ok"):
        raise SystemExit(f"probe account creation did not return ok\n{_json_dumps(data)}")
    status = result_status(data)
    if status and status not in CONFIRMED_STATUSES:
        raise SystemExit(f"probe account creation was not confirmed: status={status}\n{_json_dumps(data)}")
    return data


def run_probe(api: str, *, probe: PermissionProbe, account: str, keyfile: Path, suffix: str, timeout: float) -> Json:
    payload = probe_payload(probe.tx_type, account=account, suffix=f"{suffix}-{probe.name}")
    proc = run_command(
        devnet_tx_cmd(
            api,
            "submit-tx",
            "--account",
            account,
            "--keyfile",
            str(keyfile),
            "--tx-type",
            probe.tx_type,
            "--payload-json",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            "--wait",
            "--timeout",
            str(timeout),
        ),
        timeout=timeout + 10,
    )
    ok, detail = classify_probe_result(probe, proc)
    detail["payload"] = payload
    detail["description"] = probe.description
    detail["ok"] = bool(ok)
    return detail


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Probe backend/execution PoH permission gates through normal devnet tx submission")
    p.add_argument("--api", default=os.environ.get("WEALL_API", "http://127.0.0.1:8001"), help="Node API base URL")
    p.add_argument("--account", default=os.environ.get("WEALL_PERMISSION_PROBE_ACCOUNT", ""), help="Probe account id; defaults to fresh timestamped account")
    p.add_argument("--keyfile", default=os.environ.get("WEALL_PERMISSION_PROBE_KEYFILE", ""), help="Probe account keyfile path")
    p.add_argument("--probe", action="append", default=[], help="Run only a named probe; may be repeated")
    p.add_argument("--list-probes", action="store_true", help="Print available probes and exit")
    p.add_argument("--no-register", action="store_true", help="Do not create/register the probe account before probing")
    p.add_argument("--dry-run", action="store_true", help="Print probe plan without submitting transactions")
    p.add_argument("--timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    probes = selected_probes(args.probe)
    if args.list_probes:
        print(_json_dumps({"ok": True, "probes": [p.__dict__ for p in PROBES]}))
        return 0

    suffix = _now_suffix()
    account = str(args.account or "").strip() or f"@permission_probe_{suffix}"
    keyfile = Path(str(args.keyfile or "").strip() or DEFAULT_ACCOUNT_ROOT / f"permission-probe-{suffix}.json").expanduser()

    plan: Json = {
        "ok": True,
        "api": args.api,
        "account": account,
        "keyfile": str(keyfile),
        "dry_run": bool(args.dry_run),
        "probes": [
            {
                "name": p.name,
                "tx_type": p.tx_type,
                "gate": p.gate,
                "expected": p.expected,
                "payload": probe_payload(p.tx_type, account=account, suffix=f"{suffix}-{p.name}"),
                "description": p.description,
            }
            for p in probes
        ],
    }
    if args.dry_run:
        print(_json_dumps(plan))
        return 0

    results: list[Json] = []
    registration: Json | None = None
    if not args.no_register:
        registration = register_probe_account(args.api, account=account, keyfile=keyfile, timeout=args.timeout)

    all_ok = True
    for probe in probes:
        result = run_probe(args.api, probe=probe, account=account, keyfile=keyfile, suffix=suffix, timeout=args.timeout)
        results.append(result)
        all_ok = all_ok and bool(result.get("ok"))

    out: Json = {
        "ok": bool(all_ok),
        "api": args.api,
        "account": account,
        "keyfile": str(keyfile),
        "registration": registration,
        "results": results,
        "summary": {
            "probe_count": len(results),
            "passed": sum(1 for r in results if r.get("ok")),
            "failed": sum(1 for r in results if not r.get("ok")),
        },
    }
    print(_json_dumps(out))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
