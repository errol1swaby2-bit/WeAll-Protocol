#!/usr/bin/env python3
"""Read-only, evidence-bound two-physical-machine WeAll network rehearsal probe.

This complements, rather than replaces, the existing reviewer Genesis,
external observer, cross-machine replay, and validator-operator scripts.
It does not start nodes, sign transactions, modify state or grant authority.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "weall.two_pc_network_capture.v1"
COMPARISON_SCHEMA = "weall.two_pc_network_comparison.v1"
MAX_RESPONSE_BYTES = 262_144
MAX_PACKET_BYTES = 1_048_576
CORE_PATHS = ("/v1/status", "/v1/readyz", "/v1/chain/identity", "/v1/net/self")
NON_CLAIMS = {
    "public_beta_ready": False,
    "public_multi_validator_bft_proven": False,
    "validator_activation_proven": False,
    "live_poh_proven": False,
    "public_seed_registry_verified_by_this_tool": False,
    "physical_machine_isolation_independently_verified": False,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _sha(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _git(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), *args],
            text=True, stderr=subprocess.DEVNULL, timeout=8,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def machine_capabilities() -> dict[str, Any]:
    """Non-identifying capacity hints, not benchmarks or service health proof."""
    ram_mb = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                ram_mb = int(line.split()[1]) // 1024
                break
    except (FileNotFoundError, OSError, ValueError, IndexError):
        pass
    try:
        free_gb = round(shutil.disk_usage(ROOT).free / (1024 ** 3), 2)
    except OSError:
        free_gb = None
    return {
        "logical_cpu_count": os.cpu_count(),
        "ram_mb": ram_mb,
        "available_storage_gb": free_gb,
        "wsl_environment_detected": "microsoft" in platform.release().lower(),
        "command_available": {name: shutil.which(name) is not None for name in (
            "git", "python3", "node", "npm", "docker", "ipfs", "curl",
        )},
        "note": "Tool availability is not proof the Docker daemon or an IPFS node is running.",
    }


def repo_identity() -> dict[str, Any]:
    commit = _git("rev-parse", "HEAD") or ""
    tree = _git("rev-parse", "HEAD^{tree}") or ""
    tracked_status = _git("status", "--porcelain", "--untracked-files=no")
    return {
        "commit": commit,
        "tree": tree,
        # A failed git command is not a clean checkout.
        "tracked_tree_clean": bool(commit and tree) and tracked_status == "",
    }


def parse_api_base(raw: str, *, remote: bool, allow_lan: bool = False) -> str:
    """Do not silently accept same-machine or insecure public URLs as remote."""
    parsed = urllib.parse.urlsplit(raw.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("invalid_api_base: absolute http(s) origin without credentials required")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_api_base_port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("invalid_api_base_port")

    host = parsed.hostname.lower().rstrip(".")
    is_loopback = host == "localhost" or host.endswith(".localhost")
    private = False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        is_loopback = ip.is_loopback
        if ip.is_unspecified or ip.is_link_local or ip.is_multicast or (ip.is_reserved and not is_loopback and not ip.is_private):
            raise ValueError("non_dialable_or_special_api_address")
        private = ip.is_private

    if remote:
        if is_loopback:
            raise ValueError("remote_api_cannot_be_loopback")
        if private and not allow_lan:
            raise ValueError("private_remote_api_requires_allow_lan")
        if parsed.scheme != "https" and not (private and allow_lan):
            raise ValueError("public_remote_api_requires_https")
    elif not is_loopback:
        raise ValueError("local_api_must_be_loopback")

    # Preserve canonical URL host/port spelling without path, credentials or query.
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.lower(), "", "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: Any, msg: Any,
                         headers: Any, newurl: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch_json(base: str, path: str, *, timeout: float = 5.0) -> dict[str, Any]:
    req = urllib.request.Request(
        base + path, headers={"Accept": "application/json"}, method="GET"
    )
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise ValueError("oversize_api_response")
    except urllib.error.HTTPError as exc:
        raise ValueError(f"http_{exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ValueError("api_transport_unreachable") from None
    try:
        payload = json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_json_response") from exc
    if not isinstance(payload, dict):
        raise ValueError("api_response_not_object")
    return payload


def _probe(base: str, path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        value = fetch_json(base, path)
        return value, {"ok": True}
    except ValueError as exc:
        # Never persist raw response bodies, URL credentials or exception text.
        return {}, {"ok": False, "error_code": str(exc)}


def _chain_facts(status: dict[str, Any], readyz: dict[str, Any],
                 identity: dict[str, Any]) -> dict[str, Any]:
    manifest = _as_dict(identity.get("chain_manifest"))
    finalized = _as_dict(identity.get("finalized"))
    return {
        "chain_id": _string(identity.get("chain_id")) or _string(status.get("chain_id")),
        "genesis_hash": _string(manifest.get("genesis_hash")) or _string(identity.get("genesis_hash")),
        "tx_index_hash": _string(identity.get("tx_index_hash")) or _string(status.get("tx_index_hash")),
        "protocol_profile_hash": _string(identity.get("protocol_profile_hash")) or _string(status.get("protocol_profile_hash")),
        "status_ok": status.get("ok") is True,
        "readyz_ok": readyz.get("ok") is True,
        "chain_identity_ok": identity.get("ok") is True,
        "height": _int(identity.get("height")),
        "state_root": _string(identity.get("state_root")),
        "finalized_height": _int(finalized.get("height")),
        "finalized_block_id": _string(finalized.get("block_id")),
    }


def _network_facts(report: dict[str, Any]) -> dict[str, Any]:
    net = _as_dict(report.get("net"))
    counts = _as_dict(net.get("counts"))
    nat = _as_dict(net.get("nat"))
    return {
        "available": report.get("ok") is True,
        "enabled": report.get("enabled") is True,
        "peer_id": _string(net.get("peer_id")),
        "identity_pubkey": _string(net.get("identity_pubkey")),
        "connected_peers": _int(counts.get("connected_peers")),
        "established_sessions": _int(counts.get("established_sessions")),
        "nat_profile": _string(nat.get("recommended_profile")),
        "mesh_transport_only": nat.get("authority") == "network_transport_only",
    }


def _peer_facts(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("ok") is not True or report.get("enabled") is not True:
        return {"available": False, "peers": []}
    peers = []
    for rec in report.get("peers", []):
        if not isinstance(rec, dict):
            continue
        peer_id = _string(rec.get("peer_id"))
        if peer_id:
            peers.append({
                "peer_id": peer_id,
                "pubkey": _string(rec.get("pubkey")),
                "established": rec.get("established") is True,
                "identity_verified": rec.get("identity_verified") is True,
                "connected": rec.get("connected") is True,
            })
    return {"available": True, "peers": peers[:500]}


def _capture_endpoint(base: str, *, peer_debug: bool = False) -> dict[str, Any]:
    bodies: dict[str, dict[str, Any]] = {}
    probes: dict[str, dict[str, Any]] = {}
    for path in CORE_PATHS:
        bodies[path], probes[path] = _probe(base, path)
    debug = {"available": False, "peers": []}
    if peer_debug:
        raw, probe = _probe(base, "/v1/net/peers")
        probes["/v1/net/peers"] = probe
        debug = _peer_facts(raw)

    return {
        "probes": probes,
        "chain": _chain_facts(
            bodies["/v1/status"], bodies["/v1/readyz"],
            bodies["/v1/chain/identity"],
        ),
        "network": _network_facts(bodies["/v1/net/self"]),
        "peer_debug": debug,
    }


COMMIT_FIELDS = ("chain_id", "genesis_hash", "tx_index_hash", "protocol_profile_hash")


def _compatible(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return all(_string(a.get(k)) and _string(a.get(k)) == _string(b.get(k))
               for k in COMMIT_FIELDS)


def load_expected_commitments(path: str) -> dict[str, str]:
    """Read external/bundled chain pins; no network-provided first-node trust."""
    file = Path(path).expanduser()
    if file.stat().st_size > 262_144:
        raise ValueError("oversize_expected_commitments")
    payload = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("expected_commitments_must_be_object")
    expected = {name: _string(payload.get(name)) for name in COMMIT_FIELDS}
    if not all(expected.values()):
        raise ValueError("expected_commitments_incomplete")
    return expected


def _ready(endpoint: dict[str, Any]) -> bool:
    chain = _as_dict(endpoint.get("chain"))
    return (
        chain.get("status_ok") is True
        and chain.get("readyz_ok") is True
        and chain.get("chain_identity_ok") is True
        and all(_string(chain.get(key)) for key in COMMIT_FIELDS)
    )


def capture_machine(machine_id: str, local_api: str, remote_api: str, *,
                    allow_lan: bool = False, operator_peer_debug: bool = False,
                    expected_commitments: dict[str, str] | None = None,
                    ) -> dict[str, Any]:
    if not machine_id.strip() or len(machine_id) > 100:
        raise ValueError("machine_id_required_1_to_100_characters")
    local_base = parse_api_base(local_api, remote=False)
    remote_base = parse_api_base(remote_api, remote=True, allow_lan=allow_lan)
    local = _capture_endpoint(local_base, peer_debug=operator_peer_debug)
    # Do not read operationally sensitive peer topology from remote machines.
    remote = _capture_endpoint(remote_base)
    local_chain, remote_chain = local["chain"], remote["chain"]
    checks = {
        "local_api_ready": _ready(local),
        "remote_api_ready": _ready(remote),
        "same_chain_commitments": _compatible(local_chain, remote_chain),
        "distinct_node_identity": bool(
            _string(local["network"].get("peer_id"))
            and _string(remote["network"].get("peer_id"))
            and local["network"]["peer_id"] != remote["network"]["peer_id"]
            and _string(local["network"].get("identity_pubkey"))
            and _string(remote["network"].get("identity_pubkey"))
            and local["network"]["identity_pubkey"] != remote["network"]["identity_pubkey"]
        ),
    }
    if expected_commitments is not None:
        checks["matches_operator_pinned_chain"] = (
            _compatible(local_chain, expected_commitments)
            and _compatible(remote_chain, expected_commitments)
        )
    return {
        "schema": SCHEMA,
        "captured_utc": _utc_now(),
        "machine_id": machine_id.strip(),
        "capture_mode": "lan" if allow_lan else "public_https",
        "expected_commitments_digest": _sha(expected_commitments) if expected_commitments is not None else None,
        "machine": {
            "os_family": platform.system(),
            "python_version": platform.python_version(),
            # Machine labels and isolation are operator assertions; no hardware fingerprint.
            "physical_independence_attested": False,
        },
        "repository": repo_identity(),
        "local": local,
        "remote": remote,
        "checks": checks,
        "read_only": True,
        "no_network_mutation": True,
        "non_claims": dict(NON_CLAIMS),
        "note": "API snapshots and optional local operator peer diagnostics, not full-network or PoH proof.",
    }


def _peer_link(local: dict[str, Any], target: dict[str, Any]) -> bool:
    debug = _as_dict(local.get("peer_debug"))
    network = _as_dict(target.get("network"))
    target_peer = _string(network.get("peer_id"))
    target_key = _string(network.get("identity_pubkey"))
    if debug.get("available") is not True or not target_peer or not target_key:
        return False
    return any(
        isinstance(p, dict)
        and p.get("peer_id") == target_peer
        and p.get("pubkey") == target_key
        and p.get("established") is True
        and p.get("identity_verified") is True
        and p.get("connected") is True
        for p in debug.get("peers", [])
    )


def _exact_node(a: dict[str, Any], b: dict[str, Any]) -> bool:
    an, bn = _as_dict(a.get("network")), _as_dict(b.get("network"))
    return _compatible(_as_dict(a.get("chain")), _as_dict(b.get("chain"))) and all(
        _string(an.get(k)) and _string(an.get(k)) == _string(bn.get(k))
        for k in ("peer_id", "identity_pubkey")
    )


def compare_packets(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    for packet in (a, b):
        if packet.get("schema") != SCHEMA:
            raise ValueError("invalid_network_capture_schema")
    ar, br = _as_dict(a.get("repository")), _as_dict(b.get("repository"))
    al, bl = _as_dict(a.get("local")), _as_dict(b.get("local"))
    ax, bx = _as_dict(a.get("remote")), _as_dict(b.get("remote"))
    ac, bc = _as_dict(al.get("chain")), _as_dict(bl.get("chain"))
    same_height = ac.get("height") is not None and ac.get("height") == bc.get("height")
    roots_match = bool(
        same_height
        and _string(ac.get("state_root"))
        and ac.get("state_root") == bc.get("state_root")
    )
    finalized_match = bool(
        ac.get("finalized_height") is not None
        and ac.get("finalized_height") == bc.get("finalized_height")
        and _string(ac.get("finalized_block_id"))
        and ac.get("finalized_block_id") == bc.get("finalized_block_id")
    )
    checks = {
        "distinct_machine_labels_operator_asserted": bool(
            _string(a.get("machine_id")) and _string(b.get("machine_id"))
            and a["machine_id"] != b["machine_id"]
        ),
        "same_exact_git_commit_and_tree": bool(
            _string(ar.get("commit")) and ar.get("commit") == br.get("commit")
            and _string(ar.get("tree")) and ar.get("tree") == br.get("tree")
        ),
        "both_tracked_trees_clean": ar.get("tracked_tree_clean") is True and br.get("tracked_tree_clean") is True,
        "local_apis_ready": _ready(al) and _ready(bl),
        "bidirectional_remote_api_ready": _ready(ax) and _ready(bx),
        "same_chain_commitments": _compatible(ac, bc),
        "same_expected_commitments_digest": bool(
            (a.get("expected_commitments_digest") is None and b.get("expected_commitments_digest") is None)
            or (isinstance(a.get("expected_commitments_digest"), str)
                and a.get("expected_commitments_digest")
                == b.get("expected_commitments_digest"))
        ),
        "both_match_expected_commitments_if_supplied": bool(
            (a.get("expected_commitments_digest") is None and b.get("expected_commitments_digest") is None)
            or (_as_dict(a.get("checks")).get("matches_operator_pinned_chain") is True
                and _as_dict(b.get("checks")).get("matches_operator_pinned_chain") is True)
        ),
        "distinct_node_peer_ids": bool(
            _string(_as_dict(al.get("network")).get("peer_id"))
            and _string(_as_dict(bl.get("network")).get("peer_id"))
            and _as_dict(al.get("network")).get("peer_id") != _as_dict(bl.get("network")).get("peer_id")
        ),
        "distinct_node_public_keys": bool(
            _string(_as_dict(al.get("network")).get("identity_pubkey"))
            and _string(_as_dict(bl.get("network")).get("identity_pubkey"))
            and _as_dict(al.get("network")).get("identity_pubkey") != _as_dict(bl.get("network")).get("identity_pubkey")
        ),
        "a_observed_b_identity": _exact_node(ax, bl),
        "b_observed_a_identity": _exact_node(bx, al),
        "reciprocal_authenticated_p2p_peer_entries": _peer_link(al, bl) and _peer_link(bl, al),
        "same_height_state_root_equal": roots_match,
        "same_finalized_checkpoint": finalized_match,
    }
    core = (
        "distinct_machine_labels_operator_asserted",
        "same_exact_git_commit_and_tree", "both_tracked_trees_clean",
        "local_apis_ready", "bidirectional_remote_api_ready",
        "same_chain_commitments", "same_expected_commitments_digest",
        "both_match_expected_commitments_if_supplied", "distinct_node_peer_ids",
        "distinct_node_public_keys", "a_observed_b_identity", "b_observed_a_identity",
    )
    return {
        "schema": COMPARISON_SCHEMA,
        "compared_utc": _utc_now(),
        "machine_labels": [a.get("machine_id"), b.get("machine_id")],
        "checks": checks,
        "bidirectional_api_preflight_pass": all(checks[k] for k in core),
        "verified_peer_adjacency_pass": checks["reciprocal_authenticated_p2p_peer_entries"],
        "matching_state_root_snapshot_pass": roots_match,
        "matching_finalized_checkpoint_pass": finalized_match,
        "full_networking_test_proven": False,
        "read_only": True,
        "non_claims": dict(NON_CLAIMS),
        "note": (
            "Peer adjacency requires explicit operator-local /v1/net/peers snapshots on BOTH nodes. "
            "Matching roots require equal heights; snapshots alone never prove live PoH, "
            "durable propagation, partition/rejoin safety or physical machine independence."
        ),
    }


def _write_packet(path: str, payload: dict[str, Any]) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if target.exists() and target.is_symlink():
        raise ValueError("refuse_symlink_evidence_destination")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(data)


def _read_packet(path: str) -> dict[str, Any]:
    file = Path(path).expanduser()
    if file.stat().st_size > MAX_PACKET_BYTES:
        raise ValueError("oversize_network_capture_packet")
    payload = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("network_capture_packet_must_be_object")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    inv = sub.add_parser("inventory", help="record safe local environment metadata (no node required)")
    inv.add_argument("--machine-id", required=True)
    inv.add_argument("--out", required=True)

    capture = sub.add_parser("capture", help="read-only local and remote node API snapshots")
    capture.add_argument("--machine-id", required=True)
    capture.add_argument("--local-api", default="http://127.0.0.1:8000")
    capture.add_argument("--remote-api", required=True)
    capture.add_argument("--allow-lan", action="store_true", help="permit explicit private LAN HTTP address")
    capture.add_argument("--expected-commitments",
                         help="locally pinned chain commitments JSON (not discovered from a node)")
    capture.add_argument("--operator-peer-debug", action="store_true",
                         help="read local /v1/net/peers only if independently enabled and locally restricted")
    capture.add_argument("--out", required=True)

    compare = sub.add_parser("compare", help="compare separately captured machine A and B evidence")
    compare.add_argument("--a", required=True)
    compare.add_argument("--b", required=True)
    compare.add_argument("--out", required=True)
    compare.add_argument("--require-mesh", action="store_true")
    compare.add_argument("--require-state", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.action == "inventory":
            if not args.machine_id.strip():
                raise ValueError("machine_id_required")
            result = {
                "schema": "weall.two_pc_inventory.v1",
                "captured_utc": _utc_now(),
                "machine_id": args.machine_id,
                "repository": repo_identity(),
                "os_family": platform.system(),
                "python_version": platform.python_version(),
                "capabilities": machine_capabilities(),
                "read_only": True,
                "physical_isolation_independently_verified": False,
                "non_claims": dict(NON_CLAIMS),
            }
            _write_packet(args.out, result)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "capture":
            result = capture_machine(
                args.machine_id, args.local_api, args.remote_api,
                allow_lan=args.allow_lan, operator_peer_debug=args.operator_peer_debug,
                expected_commitments=(load_expected_commitments(args.expected_commitments)
                                      if args.expected_commitments else None),
            )
            _write_packet(args.out, result)
            print(json.dumps({"out": args.out, "checks": result["checks"]}, sort_keys=True))
            return 0 if all(result["checks"].values()) else 1

        a, b = _read_packet(args.a), _read_packet(args.b)
        result = compare_packets(a, b)
        _write_packet(args.out, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        ok = result["bidirectional_api_preflight_pass"]
        if args.require_mesh:
            ok = ok and result["verified_peer_adjacency_pass"]
        if args.require_state:
            ok = ok and result["matching_state_root_snapshot_pass"]
        return 0 if ok else 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"two_pc_network_evidence_error:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
