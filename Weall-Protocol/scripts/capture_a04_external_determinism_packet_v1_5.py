#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SEEDS = ("1", "7", "31337")
Json = dict[str, Any]


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes()) if path.is_file() else "missing"


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _run(
    args: list[str],
    *,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
) -> None:
    proc = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(args)}\n"
            f"{proc.stdout}\n{proc.stderr}"
        )


def _run_json(
    args: list[str],
    *,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
) -> Json:
    _run(args, env=env, stdout_path=stdout_path, stderr_path=stderr_path)
    payload = json.loads(stdout_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"expected JSON object from {' '.join(args)}")
    return payload


def _stable_replay_digest(payload: Json) -> str:
    material = {
        "ok": bool(payload.get("ok")),
        "chain_id": str(payload.get("chain_id") or ""),
        "source_manifest": payload.get("source_manifest"),
        "replay_manifest": payload.get("replay_manifest"),
        "issues": payload.get("issues"),
    }
    return _sha256_bytes(_canon(material).encode("utf-8"))


def _stable_db_replay_digest(payload: Json) -> str:
    keys = (
        "ok",
        "source_height",
        "fresh_height",
        "source_state_root",
        "fresh_state_root",
        "durable_db_used",
        "receipt_roots_verified",
        "interrupted_resume_verified",
        "corrupt_block_rejected",
    )
    return _sha256_bytes(
        _canon({key: payload.get(key) for key in keys}).encode("utf-8")
    )


def _stable_fresh_replay_digest(payload: Json) -> str:
    stable = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "work_dir",
            "source_db",
            "fresh_db",
            "resume_db",
            "captured_at",
            "captured_utc",
        }
    }
    return _sha256_bytes(_canon(stable).encode("utf-8"))


def _runtime_lifecycle_result(seed: str, *, env: dict[str, str], out: Path) -> Json:
    code = r"""
import hashlib
import json
from gen_tx_lifecycle_assurance_v1_5 import build_manifest

payload = build_manifest()
raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(json.dumps({
    "ok": True,
    "tx_count": int(payload["summary"]["tx_count"]),
    "successful_apply_count": int(payload["summary"]["successful_apply_count"]),
    "successful_admission_count": int(payload["summary"]["successful_admission_count"]),
    "lifecycle_runtime_digest": hashlib.sha256(raw).hexdigest(),
}, sort_keys=True))
"""
    seeded = dict(env)
    seeded["PYTHONHASHSEED"] = seed
    stdout = out / "artifacts" / f"hashseed-{seed}-lifecycle.json"
    stderr = out / "logs" / f"hashseed-{seed}-lifecycle.stderr.txt"
    return _run_json(
        [sys.executable, "-c", code],
        env=seeded,
        stdout_path=stdout,
        stderr_path=stderr,
    )


def _run_seed_regression_suite(seed: str, *, env: dict[str, str], out: Path) -> None:
    seeded = dict(env)
    seeded["PYTHONHASHSEED"] = seed
    stdout = out / "logs" / f"hashseed-{seed}-determinism-pytest.stdout.txt"
    stderr = out / "logs" / f"hashseed-{seed}-determinism-pytest.stderr.txt"
    _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_p0_scheduler_and_receipt_breadth_closure.py",
            "tests/test_helper_serial_equivalence_corpus.py",
            "tests/test_nonce_failure_block_progression.py",
            "tests/test_p2_a02_success_lifecycle_baseline.py",
            "tests/test_p2_a02_lifecycle_manifest.py",
        ],
        env=seeded,
        stdout_path=stdout,
        stderr_path=stderr,
    )


def build_local_packet(
    *,
    machine_id: str,
    operator_id: str,
    out_dir: Path,
    chain_id_prefix: str,
) -> Json:
    commit = _git("rev-parse", "HEAD")
    git_tree = _git("rev-parse", "HEAD^{tree}")
    branch = _git("branch", "--show-current")
    status = _git("status", "--short", "--untracked-files=all")
    if status.strip():
        raise RuntimeError(
            "A04 external determinism capture requires a clean checkout before evidence capture"
        )

    out = out_dir.expanduser().resolve()
    (out / "logs").mkdir(parents=True, exist_ok=True)
    (out / "artifacts").mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(ROOT / "src"),
            str(ROOT / "scripts"),
            str(env.get("PYTHONPATH") or ""),
        ]
    ).strip(os.pathsep)
    env["WEALL_MODE"] = "testnet"
    env["WEALL_REQUIRE_VRF"] = "0"

    replay = _run_json(
        [
            sys.executable,
            "scripts/replay_consistency_audit.py",
            "--work-dir",
            str(out / "replay-work"),
            "--chain-id-prefix",
            chain_id_prefix,
            "--json",
        ],
        env=env,
        stdout_path=out / "artifacts" / "replay_consistency_audit.json",
        stderr_path=out / "logs" / "replay_consistency_audit.stderr.txt",
    )
    if replay.get("ok") is not True:
        raise RuntimeError("replay_consistency_audit did not report ok=true")

    fresh = _run_json(
        [sys.executable, "scripts/rehearse_fresh_node_replay_sync_v1_5.py", "--json"],
        env=env,
        stdout_path=out / "artifacts" / "fresh_node_replay_sync.json",
        stderr_path=out / "logs" / "fresh_node_replay_sync.stderr.txt",
    )
    if fresh.get("ok") is not True:
        raise RuntimeError("fresh-node replay sync did not report ok=true")

    db_replay = _run_json(
        [sys.executable, "scripts/rehearse_db_backed_fresh_node_replay_sync_v1_5.py", "--json"],
        env=env,
        stdout_path=out / "artifacts" / "db_backed_fresh_node_replay_sync.json",
        stderr_path=out / "logs" / "db_backed_fresh_node_replay_sync.stderr.txt",
    )
    if db_replay.get("ok") is not True:
        raise RuntimeError("DB-backed replay sync did not report ok=true")

    _run(
        [sys.executable, "scripts/check_tx_canon_artifacts.py"],
        env=env,
        stdout_path=out / "logs" / "check_tx_canon_artifacts.stdout.txt",
        stderr_path=out / "logs" / "check_tx_canon_artifacts.stderr.txt",
    )
    _run(
        [sys.executable, "scripts/gen_tx_lifecycle_assurance_v1_5.py", "--check"],
        env=env,
        stdout_path=out / "logs" / "check_tx_lifecycle_assurance.stdout.txt",
        stderr_path=out / "logs" / "check_tx_lifecycle_assurance.stderr.txt",
    )

    hashseed_results: Json = {}
    for seed in SEEDS:
        result = _runtime_lifecycle_result(seed, env=env, out=out)
        _run_seed_regression_suite(seed, env=env, out=out)
        result["determinism_pytest_ok"] = True
        hashseed_results[seed] = result

    live_digests = {
        str(result.get("lifecycle_runtime_digest") or "")
        for result in hashseed_results.values()
    }
    if len(live_digests) != 1:
        raise RuntimeError("lifecycle runtime digest differs across PYTHONHASHSEED values")
    if any(int(result.get("tx_count") or 0) != 236 for result in hashseed_results.values()):
        raise RuntimeError("seeded lifecycle matrix did not execute 236 vectors")

    lifecycle_path = ROOT / "generated" / "tx_lifecycle_assurance_v1_5.json"
    semantic_path = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"
    state_root_path = ROOT / "generated" / "state_root_vectors_v1_5.json"
    tx_index_path = ROOT / "generated" / "tx_index.json"
    tx_contract_path = ROOT / "generated" / "tx_contract_map.json"

    packet: Json = {
        "schema": "weall.v1_5.external_cross_machine_replay_local_packet",
        "blocker": "AUD-618-P1-003",
        "a04_f002_scope": True,
        "machine_id": machine_id,
        "operator_id": operator_id,
        "commit": commit,
        "git_tree": git_tree,
        "branch": branch,
        "git_status_short": status,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "state_root_vectors_sha256": _sha256_file(state_root_path),
        "tx_index_sha256": _sha256_file(tx_index_path),
        "tx_contract_map_sha256": _sha256_file(tx_contract_path),
        "tx_lifecycle_assurance_sha256": _sha256_file(lifecycle_path),
        "tx_semantic_assurance_sha256": _sha256_file(semantic_path),
        "replay_consistency_ok": True,
        "fresh_node_replay_sync_ok": True,
        "db_backed_replay_sync_ok": True,
        "broad_lifecycle_corpus_ok": True,
        "scheduler_order_permutation_ok": True,
        "helper_serial_equivalence_ok": True,
        "failed_receipt_replay_ok": True,
        "hashseed_results": hashseed_results,
        "replay_manifest_digest": _stable_replay_digest(replay),
        "db_replay_digest": _stable_db_replay_digest(db_replay),
        "fresh_node_replay_digest": _stable_fresh_replay_digest(fresh),
        "state_root": str(
            replay.get("source_manifest", {}).get("computed_state_root")
            if isinstance(replay.get("source_manifest"), dict)
            else ""
        ),
        "fresh_state_root": str(
            fresh.get("fresh_state_root")
            or db_replay.get("fresh_state_root")
            or ""
        ),
        "interrupted_resume_root": str(
            fresh.get("interrupted_resume_root")
            or db_replay.get("fresh_state_root")
            or ""
        ),
        "capture_command": (
            "python scripts/capture_a04_external_determinism_packet_v1_5.py "
            f"--machine-id {machine_id} --operator-id {operator_id} "
            f"--out-dir {out_dir} --chain-id-prefix {chain_id_prefix}"
        ),
        "public_beta_ready": False,
        "mainnet_ready": False,
        "external_review_required_before_closure": True,
    }

    packet_path = out / "LOCAL_MACHINE_REPLAY_EVIDENCE.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    files: Json = {}
    for path in sorted(item for item in out.rglob("*") if item.is_file()):
        rel = path.relative_to(out).as_posix()
        files[rel] = {
            "sha256": _sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "weall.v1_5.external_cross_machine_replay_local_manifest",
                "blocker": "AUD-618-P1-003",
                "ok": True,
                "public_beta_ready": False,
                "mainnet_ready": False,
                "external_review_required_before_closure": True,
                "files": files,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return packet


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Capture one strict A04-F002 external-machine determinism packet. "
            "Two independent/physical machine packets are still required for closure."
        )
    )
    parser.add_argument("--machine-id", required=True)
    parser.add_argument("--operator-id", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--chain-id-prefix", default="external-cross-machine-replay")
    args = parser.parse_args()

    packet = build_local_packet(
        machine_id=args.machine_id,
        operator_id=args.operator_id,
        out_dir=Path(args.out_dir),
        chain_id_prefix=args.chain_id_prefix,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "packet": str(Path(args.out_dir) / "LOCAL_MACHINE_REPLAY_EVIDENCE.json"),
                "commit": packet["commit"],
                "git_tree": packet["git_tree"],
                "machine_id": packet["machine_id"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
