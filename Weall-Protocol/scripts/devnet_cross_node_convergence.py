#!/usr/bin/env python3
"""Controlled-devnet cross-node transaction convergence probe.

This harness is intentionally conservative. It uses normal public APIs and the
existing devnet transaction/sync helpers to prove that transactions submitted
through either node become visible from the other node after verified relay/sync convergence.

It does not call demo seed routes, does not copy databases, and does not mutate
state outside the normal signed transaction path.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"

Json = dict[str, Any]


class NodeUnavailable(Exception):
    """Raised when a configured devnet API is not reachable/readable."""

    def __init__(self, *, api: str, path: str, detail: str, node: str = "") -> None:
        super().__init__(detail)
        self.api = str(api)
        self.path = str(path)
        self.detail = str(detail)
        self.node = str(node or "")

    def to_json(self) -> Json:
        out: Json = {"api": self.api, "path": self.path, "detail": self.detail}
        if self.node:
            out["node"] = self.node
        return out


SCENARIOS: list[Json] = [
    {
        "name": "node1-account-register-visible-node2",
        "direction": "node1_to_node2",
        "source": "node1",
        "target": "node2",
        "tx_type": "ACCOUNT_REGISTER",
        "expect": "account_visible_on_target",
        "description": "Create a fresh account through node 1, sync node 2 from node 1, and confirm node 2 exposes the account state.",
    },
    {
        "name": "node2-profile-update-visible-node1",
        "direction": "node2_to_node1",
        "source": "node2",
        "target": "node1",
        "tx_type": "PROFILE_UPDATE",
        "expect": "tx_visible_on_target",
        "description": "Submit a normal Tier0 user transaction through node 2, then either sync node 1 from node 2 when the joiner is producing blocks or relay the exact signed tx to the canonical producer and verify both nodes converge.",
    },
    {
        "name": "state-root-identity-parity-after-bidirectional-sync",
        "direction": "bidirectional",
        "source": "node1,node2",
        "target": "node1,node2",
        "tx_type": "CHAIN_IDENTITY_COMPARE",
        "expect": "matching_height_tip_hash_state_root_tx_index_hash",
        "description": "Compare chain identity, height, tip hash, state root, schema version, tx index hash, and protocol profile hash after the bidirectional flow.",
    },
]

COMPARE_KEYS = [
    "chain_id",
    "height",
    "tip_hash",
    "state_root",
    "schema_version",
    "tx_index_hash",
    "protocol_profile_hash",
]


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _now_tag() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + f"-{os.getpid()}"


def _http_json(api: str, path: str, *, timeout: float = 15.0, node: str = "") -> Json:
    url = str(api).rstrip("/") + path
    req = urllib.request.Request(url=url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise NodeUnavailable(
            api=api,
            path=path,
            node=node,
            detail=f"HTTP {exc.code} from {url}: {body[:300]}",
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NodeUnavailable(
            api=api,
            path=path,
            node=node,
            detail=f"could not reach {url}: {exc}",
        ) from exc
    return json.loads(raw) if raw.strip() else {"ok": True}


def _http_post_json(api: str, path: str, body: Any, *, timeout: float = 15.0, node: str = "") -> Json:
    url = str(api).rstrip("/") + path
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            detail: Any = json.loads(raw)
        except Exception:
            detail = {"raw": raw}
        return {"ok": False, "http_status": exc.code, "error": detail}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NodeUnavailable(
            api=api,
            path=path,
            node=node,
            detail=f"could not reach {url}: {exc}",
        ) from exc
    return json.loads(raw) if raw.strip() else {"ok": True}


def wait_tx_status(api: str, tx_id: str, *, timeout_s: float, poll_s: float, node: str = "") -> Json:
    deadline = time.time() + float(timeout_s)
    last: Json = {"ok": False, "status": "not_checked", "tx_id": tx_id}
    while time.time() <= deadline:
        last = _tx_status(api, tx_id, timeout=float(max(0.1, poll_s)), node=node)
        status = str(last.get("status") or "").strip().lower()
        if status in {"confirmed", "committed", "applied", "invalid", "rejected"}:
            return last
        time.sleep(float(poll_s))
    return last


def relay_signed_tx_to_canonical_producer(
    *,
    producer_api: str,
    tx_path: str,
    tx_id: str,
    timeout_s: float,
    poll_s: float,
    http_timeout: float,
) -> Json:
    path = Path(tx_path).expanduser()
    if not path.exists():
        return {"ok": False, "failure": "signed_tx_file_missing", "tx_path": str(path)}
    tx = json.loads(path.read_text(encoding="utf-8"))
    submitted = _http_post_json(producer_api, "/v1/tx/submit", tx, timeout=http_timeout, node="node1")
    observed_tx_id = str(submitted.get("tx_id") or tx_id or "").strip()
    status = wait_tx_status(
        producer_api,
        observed_tx_id,
        timeout_s=timeout_s,
        poll_s=poll_s,
        node="node1",
    ) if observed_tx_id else {"ok": False, "status": "missing_tx_id"}
    ok = str(status.get("status") or "").strip().lower() in {"confirmed", "committed", "applied"}
    return {
        "ok": ok,
        "mode": "edge_relay_to_canonical_producer",
        "producer_api": producer_api,
        "tx_path": str(path),
        "tx_id": observed_tx_id,
        "submit": submitted,
        "tx_status": status,
    }




def _account_state(api: str, account: str, *, timeout: float = 15.0, node: str = "") -> Json:
    quoted = urllib.parse.quote(str(account or "").strip(), safe="")
    out = _http_json(api, f"/v1/accounts/{quoted}", timeout=timeout, node=node)
    state = out.get("state") if isinstance(out, dict) else None
    return state if isinstance(state, dict) else {}


def _tx_status(api: str, tx_id: str, *, timeout: float = 15.0, node: str = "") -> Json:
    quoted = urllib.parse.quote(str(tx_id or "").strip(), safe="")
    return _http_json(api, f"/v1/tx/status/{quoted}", timeout=timeout, node=node)


def _run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    if env:
        merged.update({k: str(v) for k, v in env.items()})
    return subprocess.run(
        cmd,
        cwd=str(cwd or REPO_ROOT),
        env=merged,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _run_json(cmd: list[str], *, env: dict[str, str] | None = None, timeout: float = 120.0) -> Json:
    proc = _run(cmd, env=env, timeout=timeout)
    if proc.returncode != 0:
        raise SystemExit(
            "command failed:\n"
            + " ".join(cmd)
            + f"\nexit={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    try:
        return json.loads(proc.stdout)
    except Exception as exc:
        raise SystemExit(
            "command did not return JSON:\n"
            + " ".join(cmd)
            + f"\nstdout={proc.stdout}\nstderr={proc.stderr}"
        ) from exc


def _sync(source_api: str, target_api: str, *, join_anchor_path: str = "", timeout: float = 180.0) -> Json:
    env: dict[str, str] = {}
    if join_anchor_path:
        env["WEALL_JOIN_ANCHOR_PATH"] = join_anchor_path
        env["WEALL_DEVNET_REQUIRE_JOIN_ANCHOR"] = "1"
    proc = _run(
        ["bash", str(SCRIPTS_DIR / "devnet_sync_from_peer.sh"), source_api, target_api],
        env=env,
        timeout=timeout,
    )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "source_api": source_api,
        "target_api": target_api,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def compare_identities(left: Json, right: Json) -> list[Json]:
    mismatches: list[Json] = []
    for key in COMPARE_KEYS:
        if left.get(key) != right.get(key):
            mismatches.append({"field": key, "node1": left.get(key), "node2": right.get(key)})
    return mismatches


def classify_tx_visibility(*, status: Json, expected_status: str = "confirmed") -> tuple[bool, Json]:
    actual = str(status.get("status") or "").strip().lower()
    expected = str(expected_status or "confirmed").strip().lower()
    ok = actual == expected
    detail: Json = {"ok": ok, "expected_status": expected, "actual_status": actual, "status": status}
    if not ok:
        detail["failure"] = "tx_not_visible_with_expected_status"
    return ok, detail


def node_unavailable_result(plan: Json, exc: NodeUnavailable) -> Json:
    return {
        **plan,
        "ok": False,
        "dry_run": False,
        "failure": "node_api_unreachable",
        "unreachable": exc.to_json(),
        "next_steps": [
            "Start node 1 in one terminal: bash scripts/devnet_boot_genesis_node.sh",
            "Start node 2 in a second terminal: bash scripts/devnet_boot_joining_node.sh",
            "Wait until both /v1/readyz endpoints are reachable, then rerun: bash scripts/devnet_cross_node_convergence.sh",
        ],
    }


def _plan(args: argparse.Namespace) -> Json:
    workspace = str(Path(args.workspace).expanduser())
    account = args.account or f"@devnet_crossnode_{_now_tag()}"
    keyfile = str(Path(workspace) / "cross-node-account.json")
    return {
        "ok": True,
        "dry_run": bool(args.dry_run),
        "node1_api": args.node1_api,
        "node2_api": args.node2_api,
        "workspace": workspace,
        "account": account,
        "keyfile": keyfile,
        "join_anchor_path": args.join_anchor_path,
        "scenarios": SCENARIOS,
        "steps": [
            {"step": "read_node_identities", "apis": [args.node1_api, args.node2_api]},
            {"step": "create_account", "api": "node1", "tx_type": "ACCOUNT_REGISTER", "uses": "scripts/devnet_tx.py create-account"},
            {"step": "sync", "direction": "node1_to_node2", "uses": "scripts/devnet_sync_from_peer.sh"},
            {"step": "assert_account_visible", "api": "node2"},
            {"step": "submit_profile_update", "api": "node2", "tx_type": "PROFILE_UPDATE", "uses": "scripts/devnet_tx.py submit-tx"},
            {"step": "converge_node2_tx", "mode": "node2_producer_or_edge_relay_to_node1", "uses": "scripts/devnet_sync_from_peer.sh or exact signed tx relay"},
            {"step": "compare_state_roots", "uses": "scripts/devnet_compare_state_roots.sh"},
        ],
    }


def run_probe(args: argparse.Namespace) -> Json:
    plan = _plan(args)
    workspace = Path(plan["workspace"])
    workspace.mkdir(parents=True, exist_ok=True)
    account = str(plan["account"])
    keyfile = str(plan["keyfile"])

    result: Json = {**plan, "dry_run": False, "events": []}

    try:
        node1_identity_before = _http_json(args.node1_api, "/v1/chain/identity", timeout=args.http_timeout, node="node1")
        node2_identity_before = _http_json(args.node2_api, "/v1/chain/identity", timeout=args.http_timeout, node="node2")
    except NodeUnavailable as exc:
        return node_unavailable_result(plan, exc)
    result["events"].append({"step": "identity_before", "node1": node1_identity_before, "node2": node2_identity_before})

    create = _run_json(
        [
            sys.executable,
            str(SCRIPTS_DIR / "devnet_tx.py"),
            "--api",
            args.node1_api,
            "create-account",
            "--account",
            account,
            "--keyfile",
            keyfile,
            "--fresh",
            "--wait",
            "--timeout",
            str(args.tx_timeout),
            "--poll",
            str(args.tx_poll),
        ],
        timeout=args.command_timeout,
    )
    result["events"].append({"step": "node1_create_account", "result": create})
    create_tx = str(create.get("tx_id") or "")
    if not create_tx:
        raise SystemExit("ACCOUNT_REGISTER did not return tx_id")

    sync_12 = _sync(args.node1_api, args.node2_api, join_anchor_path=args.join_anchor_path, timeout=args.command_timeout)
    result["events"].append({"step": "sync_node1_to_node2", "result": sync_12})
    if not sync_12["ok"]:
        result["ok"] = False
        result["failure"] = "sync_node1_to_node2_failed"
        return result

    node2_account = _account_state(args.node2_api, account, timeout=args.http_timeout, node="node2")
    result["events"].append({"step": "node2_account_after_sync", "account_state": node2_account})
    if not node2_account:
        result["ok"] = False
        result["failure"] = "account_not_visible_on_node2"
        return result

    profile_payload = {
        "display_name": "Cross-node convergence probe",
        "bio": f"submitted-through-node2:{_now_tag()}",
    }
    profile_tx_path = str(workspace / "node2-profile-update.signed-tx.json")
    submit = _run_json(
        [
            sys.executable,
            str(SCRIPTS_DIR / "devnet_tx.py"),
            "--api",
            args.node2_api,
            "submit-tx",
            "--account",
            account,
            "--keyfile",
            keyfile,
            "--tx-type",
            "PROFILE_UPDATE",
            "--payload-json",
            json.dumps(profile_payload, sort_keys=True),
            "--tx-out",
            profile_tx_path,
            "--wait",
            "--timeout",
            str(args.tx_timeout),
            "--poll",
            str(args.tx_poll),
        ],
        timeout=args.command_timeout,
    )
    result["events"].append({"step": "node2_profile_update", "result": submit})
    profile_tx = str(submit.get("tx_id") or "")
    if not profile_tx:
        result["ok"] = False
        result["failure"] = "profile_update_missing_tx_id"
        return result

    node2_submit_status = str((submit.get("tx_status") or {}).get("status") or "").strip().lower()
    result["node2_profile_update_confirmation_mode"] = "node2_local_producer" if node2_submit_status in {"confirmed", "committed", "applied"} else "edge_relay_to_node1"
    if node2_submit_status in {"confirmed", "committed", "applied"}:
        sync_21 = _sync(args.node2_api, args.node1_api, join_anchor_path=args.join_anchor_path, timeout=args.command_timeout)
        result["events"].append({"step": "sync_node2_to_node1", "result": sync_21})
        if not sync_21["ok"]:
            result["ok"] = False
            result["failure"] = "sync_node2_to_node1_failed"
            return result
    else:
        result["events"].append(
            {
                "step": "node2_profile_update_pending_edge_relay_required",
                "status": submit.get("tx_status") or {},
                "reason": "joining node accepted the tx but is not currently producing blocks",
            }
        )
        relay = relay_signed_tx_to_canonical_producer(
            producer_api=args.node1_api,
            tx_path=profile_tx_path,
            tx_id=profile_tx,
            timeout_s=args.tx_timeout,
            poll_s=args.tx_poll,
            http_timeout=args.http_timeout,
        )
        result["events"].append({"step": "relay_node2_signed_tx_to_node1", "result": relay})
        if not relay.get("ok"):
            result["ok"] = False
            result["failure"] = "relay_node2_tx_to_node1_failed"
            return result
        sync_12_after_relay = _sync(args.node1_api, args.node2_api, join_anchor_path=args.join_anchor_path, timeout=args.command_timeout)
        result["events"].append({"step": "sync_node1_to_node2_after_relay", "result": sync_12_after_relay})
        if not sync_12_after_relay["ok"]:
            result["ok"] = False
            result["failure"] = "sync_node1_to_node2_after_relay_failed"
            return result

    try:
        node1_identity_after = _http_json(args.node1_api, "/v1/chain/identity", timeout=args.http_timeout, node="node1")
        node2_identity_after = _http_json(args.node2_api, "/v1/chain/identity", timeout=args.http_timeout, node="node2")
    except NodeUnavailable as exc:
        return node_unavailable_result(plan, exc)
    mismatches = compare_identities(node1_identity_after, node2_identity_after)
    result["identity_after"] = {"node1": node1_identity_after, "node2": node2_identity_after, "mismatches": mismatches}
    if mismatches:
        result["ok"] = False
        result["failure"] = "identity_mismatch_after_bidirectional_sync"
        return result

    node1_status = _tx_status(args.node1_api, profile_tx, timeout=args.http_timeout, node="node1")
    ok_visible, visibility = classify_tx_visibility(status=node1_status)
    result["profile_update_visibility_on_node1"] = visibility
    if not ok_visible:
        result["ok"] = False
        result["failure"] = "node2_tx_not_visible_on_node1"
        return result

    result["ok"] = True
    result["account"] = account
    result["account_register_tx_id"] = create_tx
    result["profile_update_tx_id"] = profile_tx
    return result


def cmd_list_scenarios(_args: argparse.Namespace) -> int:
    print(_json_dumps({"ok": True, "scenarios": SCENARIOS}))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if args.dry_run:
        print(_json_dumps(_plan(args)))
        return 0
    plan = _plan(args)
    try:
        out = run_probe(args)
    except NodeUnavailable as exc:
        out = node_unavailable_result(plan, exc)
    print(_json_dumps(out))
    return 0 if out.get("ok") is True else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Controlled-devnet cross-node convergence probe")
    p.add_argument("--node1-api", default=os.environ.get("NODE1_API", "http://127.0.0.1:8001"))
    p.add_argument("--node2-api", default=os.environ.get("NODE2_API", "http://127.0.0.1:8002"))
    p.add_argument("--workspace", default=os.environ.get("WEALL_DEVNET_CROSS_NODE_DIR", str(REPO_ROOT / ".weall-devnet" / "cross-node")))
    p.add_argument("--account", default=os.environ.get("WEALL_CROSS_NODE_ACCOUNT", ""))
    p.add_argument("--join-anchor-path", default=os.environ.get("WEALL_JOIN_ANCHOR_PATH", ""))
    p.add_argument("--tx-timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30")))
    p.add_argument("--tx-poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5")))
    p.add_argument("--command-timeout", type=float, default=float(os.environ.get("WEALL_CROSS_NODE_COMMAND_TIMEOUT", "180")))
    p.add_argument("--http-timeout", type=float, default=float(os.environ.get("WEALL_CROSS_NODE_HTTP_TIMEOUT", "5")))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--list-scenarios", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_scenarios:
        return cmd_list_scenarios(args)
    return cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
