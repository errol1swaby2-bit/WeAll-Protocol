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
import secrets
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


def _http_post_json(
    api: str, path: str, body: Any, *, timeout: float = 15.0, node: str = ""
) -> Json:
    url = str(api).rstrip("/") + path
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
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


def wait_tx_status(
    api: str, tx_id: str, *, timeout_s: float, poll_s: float, node: str = ""
) -> Json:
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
    submitted = _http_post_json(
        producer_api, "/v1/tx/submit", tx, timeout=http_timeout, node="node1"
    )
    observed_tx_id = str(submitted.get("tx_id") or tx_id or "").strip()
    status = (
        wait_tx_status(
            producer_api,
            observed_tx_id,
            timeout_s=timeout_s,
            poll_s=poll_s,
            node="node1",
        )
        if observed_tx_id
        else {"ok": False, "status": "missing_tx_id"}
    )
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


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
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


def _sync(
    source_api: str, target_api: str, *, join_anchor_path: str = "", timeout: float = 180.0
) -> Json:
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


def chain_manifest_failures(identity: Json, *, node: str) -> list[Json]:
    manifest = identity.get("chain_manifest")
    if not isinstance(manifest, dict):
        return [{"node": node, "failure": "chain_manifest_status_missing"}]

    failures: list[Json] = []
    if manifest.get("ok") is not True:
        failures.append(
            {
                "node": node,
                "failure": "chain_manifest_not_ok",
                "issues": list(manifest.get("issues") or []),
            }
        )
    if str(manifest.get("mode") or "").strip().lower() != "controlled_devnet":
        failures.append(
            {
                "node": node,
                "failure": "chain_manifest_mode_not_controlled_devnet",
                "actual": manifest.get("mode"),
            }
        )
    if manifest.get("tx_index_hash_matches") is not True:
        failures.append(
            {
                "node": node,
                "failure": "chain_manifest_tx_index_hash_not_current",
                "expected": manifest.get("tx_index_hash"),
                "actual": manifest.get("actual_tx_index_hash"),
            }
        )
    return failures


def classify_tx_visibility(
    *, status: Json, expected_status: str = "confirmed"
) -> tuple[bool, Json]:
    actual = str(status.get("status") or "").strip().lower()
    expected = str(expected_status or "confirmed").strip().lower()
    ok = actual == expected
    detail: Json = {
        "ok": ok,
        "expected_status": expected,
        "actual_status": actual,
        "status": status,
    }
    if not ok:
        detail["failure"] = "tx_not_visible_with_expected_status"
    return ok, detail


def rejected_receipt_mismatches(
    producer: Json, follower: Json, *, tx_id: str, account: str
) -> list[str]:
    """Compare *committed* failed-apply receipts from two distinct APIs.

    An HTTP error, pending status or indexed-only synthetic result is not a
    consensus execution receipt. The producer and follower must agree on the
    actual block, signer and deterministic failure detail.
    """
    failures: list[str] = []
    for label, status in (("producer", producer), ("follower", follower)):
        if str(status.get("tx_id") or "") != tx_id:
            failures.append(f"{label}_tx_id_mismatch")
        if str(status.get("status") or "") != "rejected":
            failures.append(f"{label}_not_rejected")
        if str(status.get("source") or "") != "committed_apply_receipt":
            failures.append(f"{label}_not_committed_apply_receipt")
        if status.get("apply_ok") is not False:
            failures.append(f"{label}_apply_not_false")
        if status.get("local_state_synced") is not True:
            failures.append(f"{label}_not_locally_synced")
        if int(status.get("height") or 0) < 1:
            failures.append(f"{label}_no_committed_height")
        if not str(status.get("block_id") or ""):
            failures.append(f"{label}_no_committed_block_id")
        if str(status.get("tx_type") or "") != "ACCOUNT_SESSION_KEY_REVOKE":
            failures.append(f"{label}_wrong_type")
        if str(status.get("signer") or "") != account:
            failures.append(f"{label}_wrong_signer")
        if str(status.get("code") or "") != "invalid_tx":
            failures.append(f"{label}_wrong_code")
        if str(status.get("reason") or "") != "unknown_session_key":
            failures.append(f"{label}_wrong_reason")
    for key in (
        "tx_id",
        "height",
        "block_id",
        "included_ts_ms",
        "tx_type",
        "signer",
        "code",
        "reason",
        "apply_ok",
        "status",
        "source",
        "local_state_synced",
    ):
        if producer.get(key) != follower.get(key):
            failures.append(f"cross_node_{key}_mismatch")
    return failures


def run_rejected_receipt_probe(
    args: argparse.Namespace, *, workspace: Path, account: str, keyfile: str
) -> Json:
    """Opt-in, real two-process devnet receipt convergence via public APIs.

    The joining node is an observer/catch-up participant, NOT an independent
    validator or a source of BFT quorum evidence. Never report this as QC.
    """
    evidence: Json = {
        "ok": False,
        "claim": "controlled_two_process_producer_follower_verified_sync_only",
        "multi_validator_bft_claimed": False,
        "events": [],
    }
    before = _account_state(args.node1_api, account, timeout=args.http_timeout, node="node1")
    original_nonce = int(before.get("nonce") or 0)
    if original_nonce < 1:
        evidence["failure"] = "registered_account_nonce_missing"
        return evidence

    unknown_session_key = "f1b_unissued_" + secrets.token_hex(24)
    reject_envelope_path = workspace / "f1b-committed-rejected.signed-tx.json"
    signed_reject = _run_json(
        [
            sys.executable,
            str(SCRIPTS_DIR / "devnet_tx.py"),
            "--api",
            args.node1_api,
            "submit-tx",
            "--account",
            account,
            "--keyfile",
            keyfile,
            "--tx-type",
            "ACCOUNT_SESSION_KEY_REVOKE",
            "--payload-json",
            json.dumps({"session_key": unknown_session_key}),
            "--nonce",
            str(original_nonce + 1),
            "--tx-out",
            str(reject_envelope_path),
            "--wait",
            "--timeout",
            str(args.tx_timeout),
            "--poll",
            str(args.tx_poll),
        ],
        timeout=args.command_timeout,
    )
    tx_id = str(signed_reject.get("tx_id") or "")
    evidence["events"].append(
        {
            "step": "producer_signed_revoke_unknown_session",
            "tx_id": tx_id,
            "http_admitted": signed_reject.get("submit", {}).get("ok") is True,
            "initial_status": signed_reject.get("tx_status", {}).get("status"),
        }
    )
    if not tx_id.startswith("tx:") or signed_reject.get("submit", {}).get("ok") is not True:
        evidence["failure"] = "producer_signed_rejection_not_http_admitted"
        return evidence

    producer_status = wait_tx_status(
        args.node1_api,
        tx_id,
        timeout_s=args.tx_timeout,
        poll_s=args.tx_poll,
        node="node1",
    )
    evidence["producer_status"] = producer_status
    if rejected_receipt_mismatches(producer_status, producer_status, tx_id=tx_id, account=account):
        evidence["failure"] = "producer_missing_committed_failed_apply_receipt"
        return evidence
    producer_account = _account_state(
        args.node1_api, account, timeout=args.http_timeout, node="node1"
    )
    if int(producer_account.get("nonce") or 0) != original_nonce + 1:
        evidence["failure"] = "failed_apply_nonce_not_consumed_exactly_once"
        return evidence

    sync = _sync(
        args.node1_api,
        args.node2_api,
        join_anchor_path=args.join_anchor_path,
        timeout=args.command_timeout,
    )
    evidence["events"].append(
        {
            "step": "verified_delta_sync_of_failed_receipt",
            "sync_ok": sync.get("ok") is True,
            "mode": "existing_verified_delta_sync",
        }
    )
    if sync.get("ok") is not True:
        evidence["failure"] = "failed_receipt_verified_sync_failed"
        return evidence

    follower_status = _tx_status(args.node2_api, tx_id, timeout=args.http_timeout, node="node2")
    evidence["follower_status"] = follower_status
    mismatches = rejected_receipt_mismatches(
        producer_status, follower_status, tx_id=tx_id, account=account
    )
    evidence["receipt_mismatches"] = mismatches
    if mismatches:
        evidence["failure"] = "cross_node_committed_rejected_receipt_mismatch"
        return evidence

    follower_account = _account_state(
        args.node2_api, account, timeout=args.http_timeout, node="node2"
    )
    if int(follower_account.get("nonce") or 0) != original_nonce + 1:
        evidence["failure"] = "follower_failed_apply_nonce_mismatch"
        return evidence

    # One exact replay only, after the receipt is known to both nodes.
    # Never construct an alternate envelope or automatically resubmit.
    signed_bytes = json.loads(reject_envelope_path.read_text(encoding="utf-8"))
    replay = _http_post_json(
        args.node1_api,
        "/v1/tx/submit",
        signed_bytes,
        timeout=args.http_timeout,
        node="node1",
    )
    error = replay.get("error")
    code = (
        str((error.get("error") or {}).get("code") or error.get("code") or "")
        if isinstance(error, dict)
        else ""
    )
    evidence["replay"] = {"http_status": replay.get("http_status"), "error_code": code}
    if replay.get("ok") is not False or int(replay.get("http_status") or 0) != 403:
        evidence["failure"] = "exact_rejected_envelope_replay_admitted"
        return evidence
    if code != "already_finalized_rejected":
        evidence["failure"] = "exact_replay_wrong_rejection_reason"
        return evidence
    if (
        int(
            _account_state(args.node1_api, account, timeout=args.http_timeout, node="node1").get(
                "nonce"
            )
            or 0
        )
        != original_nonce + 1
    ):
        evidence["failure"] = "replay_consumed_nonce_again"
        return evidence

    new_session = "f1b_distinct_issued_" + secrets.token_hex(24)
    issued = _run_json(
        [
            sys.executable,
            str(SCRIPTS_DIR / "devnet_tx.py"),
            "--api",
            args.node1_api,
            "submit-tx",
            "--account",
            account,
            "--keyfile",
            keyfile,
            "--tx-type",
            "ACCOUNT_SESSION_KEY_ISSUE",
            "--payload-json",
            json.dumps({"session_key": new_session, "ttl_s": 3600}),
            "--nonce",
            str(original_nonce + 2),
            "--wait",
            "--timeout",
            str(args.tx_timeout),
            "--poll",
            str(args.tx_poll),
        ],
        timeout=args.command_timeout,
    )
    issued_id = str(issued.get("tx_id") or "")
    issued_status = issued.get("tx_status") if isinstance(issued.get("tx_status"), dict) else {}
    evidence["events"].append(
        {
            "step": "producer_next_nonce_recovery",
            "tx_id": issued_id,
            "status": issued_status.get("status"),
        }
    )
    if not issued_id.startswith("tx:") or issued_status.get("status") != "confirmed":
        evidence["failure"] = "next_nonce_recovery_not_confirmed"
        return evidence

    sync_issue = _sync(
        args.node1_api,
        args.node2_api,
        join_anchor_path=args.join_anchor_path,
        timeout=args.command_timeout,
    )
    if sync_issue.get("ok") is not True:
        evidence["failure"] = "next_nonce_verified_sync_failed"
        return evidence
    node2_issued = _tx_status(args.node2_api, issued_id, timeout=args.http_timeout, node="node2")
    if node2_issued.get("status") != "confirmed" or node2_issued.get("apply_ok") is not True:
        evidence["failure"] = "follower_next_nonce_confirmation_mismatch"
        return evidence
    for label, api in (("node1", args.node1_api), ("node2", args.node2_api)):
        state = _account_state(api, account, timeout=args.http_timeout, node=label)
        if int(state.get("nonce") or 0) != original_nonce + 2:
            evidence["failure"] = f"{label}_recovery_nonce_mismatch"
            return evidence

    left = _http_json(
        args.node1_api,
        "/v1/chain/identity",
        timeout=args.http_timeout,
        node="node1",
    )
    right = _http_json(
        args.node2_api,
        "/v1/chain/identity",
        timeout=args.http_timeout,
        node="node2",
    )
    identity_mismatches = compare_identities(left, right)
    evidence["identity_mismatches"] = identity_mismatches
    if identity_mismatches:
        evidence["failure"] = "cross_node_identity_mismatch_after_rejection_recovery"
        return evidence
    evidence["ok"] = True
    evidence["rejected_tx_id"] = tx_id
    evidence["recovery_tx_id"] = issued_id
    evidence["height"] = producer_status.get("height")
    evidence["block_id"] = producer_status.get("block_id")
    evidence["final_state_root"] = left.get("state_root")
    return evidence


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
    rejected_scenario = {
        "name": "node1-failed-apply-receipt-visible-node2",
        "direction": "node1_to_node2",
        "source": "node1",
        "target": "node2",
        "tx_type": "ACCOUNT_SESSION_KEY_REVOKE",
        "expect": "same_committed_failed_apply_receipt_after_verified_delta_sync",
        "description": "One signed but deterministically rejected inclusion, replay refusal and next-nonce recovery; producer and follower must agree. No BFT QC claim.",
    }
    scenarios = [*SCENARIOS]
    if args.check_rejected_receipt:
        scenarios.append(rejected_scenario)
    return {
        "ok": True,
        "dry_run": bool(args.dry_run),
        "node1_api": args.node1_api,
        "node2_api": args.node2_api,
        "workspace": workspace,
        "account": account,
        "keyfile": keyfile,
        "join_anchor_path": args.join_anchor_path,
        "scenarios": scenarios,
        "steps": [
            {"step": "read_node_identities", "apis": [args.node1_api, args.node2_api]},
            {
                "step": "create_account",
                "api": "node1",
                "tx_type": "ACCOUNT_REGISTER",
                "uses": "scripts/devnet_tx.py create-account",
            },
            {
                "step": "sync",
                "direction": "node1_to_node2",
                "uses": "scripts/devnet_sync_from_peer.sh",
            },
            {"step": "assert_account_visible", "api": "node2"},
            {
                "step": "submit_profile_update",
                "api": "node2",
                "tx_type": "PROFILE_UPDATE",
                "uses": "scripts/devnet_tx.py submit-tx",
            },
            {
                "step": "converge_node2_tx",
                "mode": "node2_producer_or_edge_relay_to_node1",
                "uses": "scripts/devnet_sync_from_peer.sh or exact signed tx relay",
            },
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
        node1_identity_before = _http_json(
            args.node1_api, "/v1/chain/identity", timeout=args.http_timeout, node="node1"
        )
        node2_identity_before = _http_json(
            args.node2_api, "/v1/chain/identity", timeout=args.http_timeout, node="node2"
        )
    except NodeUnavailable as exc:
        return node_unavailable_result(plan, exc)
    result["events"].append(
        {"step": "identity_before", "node1": node1_identity_before, "node2": node2_identity_before}
    )
    manifest_failures_before = [
        *chain_manifest_failures(node1_identity_before, node="node1"),
        *chain_manifest_failures(node2_identity_before, node="node2"),
    ]
    result["chain_manifest_before"] = {
        "ok": not manifest_failures_before,
        "failures": manifest_failures_before,
    }
    if manifest_failures_before:
        result["ok"] = False
        result["failure"] = "chain_manifest_invalid_before_probe"
        return result

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

    sync_12 = _sync(
        args.node1_api,
        args.node2_api,
        join_anchor_path=args.join_anchor_path,
        timeout=args.command_timeout,
    )
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
    result["node2_profile_update_confirmation_mode"] = (
        "node2_local_producer"
        if node2_submit_status in {"confirmed", "committed", "applied"}
        else "edge_relay_to_node1"
    )
    if node2_submit_status in {"confirmed", "committed", "applied"}:
        sync_21 = _sync(
            args.node2_api,
            args.node1_api,
            join_anchor_path=args.join_anchor_path,
            timeout=args.command_timeout,
        )
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
        sync_12_after_relay = _sync(
            args.node1_api,
            args.node2_api,
            join_anchor_path=args.join_anchor_path,
            timeout=args.command_timeout,
        )
        result["events"].append(
            {"step": "sync_node1_to_node2_after_relay", "result": sync_12_after_relay}
        )
        if not sync_12_after_relay["ok"]:
            result["ok"] = False
            result["failure"] = "sync_node1_to_node2_after_relay_failed"
            return result

    try:
        node1_identity_after = _http_json(
            args.node1_api, "/v1/chain/identity", timeout=args.http_timeout, node="node1"
        )
        node2_identity_after = _http_json(
            args.node2_api, "/v1/chain/identity", timeout=args.http_timeout, node="node2"
        )
    except NodeUnavailable as exc:
        return node_unavailable_result(plan, exc)
    mismatches = compare_identities(node1_identity_after, node2_identity_after)
    manifest_failures_after = [
        *chain_manifest_failures(node1_identity_after, node="node1"),
        *chain_manifest_failures(node2_identity_after, node="node2"),
    ]
    result["identity_after"] = {
        "node1": node1_identity_after,
        "node2": node2_identity_after,
        "mismatches": mismatches,
        "chain_manifest_failures": manifest_failures_after,
    }
    if manifest_failures_after:
        result["ok"] = False
        result["failure"] = "chain_manifest_invalid_after_bidirectional_sync"
        return result
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

    if args.check_rejected_receipt:
        receipt_proof = run_rejected_receipt_probe(
            args, workspace=workspace, account=account, keyfile=keyfile
        )
        result["rejected_receipt_probe"] = receipt_proof
        result["events"].append(
            {
                "step": "two_process_verified_rejected_receipt",
                "ok": receipt_proof.get("ok") is True,
            }
        )
        if receipt_proof.get("ok") is not True:
            result["ok"] = False
            result["failure"] = str(
                receipt_proof.get("failure") or "cross_node_rejected_receipt_probe_failed"
            )
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
    p.add_argument(
        "--workspace",
        default=os.environ.get(
            "WEALL_DEVNET_CROSS_NODE_DIR", str(REPO_ROOT / ".weall-devnet" / "cross-node")
        ),
    )
    p.add_argument("--account", default=os.environ.get("WEALL_CROSS_NODE_ACCOUNT", ""))
    p.add_argument("--join-anchor-path", default=os.environ.get("WEALL_JOIN_ANCHOR_PATH", ""))
    p.add_argument(
        "--tx-timeout", type=float, default=float(os.environ.get("WEALL_TX_WAIT_TIMEOUT", "30"))
    )
    p.add_argument(
        "--tx-poll", type=float, default=float(os.environ.get("WEALL_TX_WAIT_POLL", "0.5"))
    )
    p.add_argument(
        "--command-timeout",
        type=float,
        default=float(os.environ.get("WEALL_CROSS_NODE_COMMAND_TIMEOUT", "180")),
    )
    p.add_argument(
        "--http-timeout",
        type=float,
        default=float(os.environ.get("WEALL_CROSS_NODE_HTTP_TIMEOUT", "5")),
    )
    p.add_argument(
        "--check-rejected-receipt",
        action="store_true",
        default=os.environ.get("WEALL_DEVNET_CHECK_REJECTED_RECEIPT", "0") == "1",
        help="Require signed canonical failed-apply receipt agreement after verified two-process devnet sync",
    )
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
