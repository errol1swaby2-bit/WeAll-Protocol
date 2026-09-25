#!/usr/bin/env python3
from __future__ import annotations

import ast
import runpy
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
REPO_ROOT = PROJECT_ROOT.parent
BOOTSTRAP = HERE / "bootstrap_r20_remediation.py"
ORIGINAL_COMMIT = "eaed26dcc79fe5ffce1c7a937e4b73f6d070566d"
ORIGINAL_REL = "Weall-Protocol/scripts/patch_r20_materialized_drivers.py"
ORIGINAL_BLOB = "a897e403daf480adcf708c1f4e3696bdf27409fe"
TEMP_IMPL = HERE / ".r20_materialized_driver_patcher_original.py"

NEW_REPAIR_FUNCTION = """def _apply_post_transform_repair(here: Path) -> None:
    project_root = here.parent
    repo_root = project_root.parent
    try:
        project_rel = project_root.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise SystemExit(
            f"unable to bind r20 project root to repository root: {project_root} vs {repo_root}"
        ) from exc
    if project_rel != "Weall-Protocol":
        raise SystemExit(f"unexpected r20 project directory: {project_rel}")

    payload_path = here / "r20_post_transform_repair.patch.gz.b64"
    encoded = payload_path.read_text(encoding="ascii").strip()
    raw = gzip.decompress(base64.b64decode(encoded))
    actual = hashlib.sha256(raw).hexdigest()
    if actual != POST_TRANSFORM_REPAIR_SHA256:
        raise SystemExit(
            f"post-transform repair digest mismatch: {actual} != {POST_TRANSFORM_REPAIR_SHA256}"
        )

    patch_path = project_root / "generated" / "r20_post_transform_repair.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_bytes(raw)
    apply_cmd = [
        "git",
        "apply",
        f"--directory={project_rel}",
        str(patch_path),
    ]
    try:
        subprocess.run(
            apply_cmd[:2] + ["--check"] + apply_cmd[2:],
            cwd=repo_root,
            check=True,
        )
        subprocess.run(apply_cmd, cwd=repo_root, check=True)
    finally:
        patch_path.unlink(missing_ok=True)

    sentinels = {
        "tests/test_helper_instance_corpus.py": (
            'assert summary["proven_helper_eligible_count"] == 0',
            'assert summary["proven_helper_eligible_count"] == 13',
        ),
        "tests/test_reputation_accrual_policy.py": (
            '"delta_milli": 10',
            '"delta": 0.01',
        ),
        "src/weall/runtime/apply/storage.py": (
            '"reassignment": reassignment',
            'rec["latest_reassignment"] = _maybe_reassign_failed_pin_target',
        ),
    }
    for rel, (required, forbidden) in sentinels.items():
        text = (project_root / rel).read_text(encoding="utf-8")
        if required not in text or forbidden in text:
            raise SystemExit(
                f"post-transform repair scope verification failed for {rel}: "
                f"required={required!r} forbidden={forbidden!r}"
            )

    stable_ids_path = project_root / "specs" / "v2" / "source" / "stable_ids.json"
    stable_ids = json.loads(stable_ids_path.read_text(encoding="utf-8"))
    entries = stable_ids.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("stable_ids.json entries must be a list")

    canonical_key = "Storage:reassigned"
    stable_id = "STATE-878383D78A5EBBC1"
    derived = "STATE-" + hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16].upper()
    if derived != stable_id:
        raise SystemExit(
            f"Storage:reassigned stable-id derivation mismatch: {derived} != {stable_id}"
        )

    matching_key = [
        row
        for row in entries
        if isinstance(row, dict)
        and str(row.get("kind") or "") == "state"
        and str(row.get("canonical_key") or "") == canonical_key
    ]
    if len(matching_key) > 1:
        raise SystemExit(f"duplicate stable-id rows for state:{canonical_key}")
    if matching_key:
        row = matching_key[0]
        if str(row.get("stable_id") or "") != stable_id:
            raise SystemExit(
                f"state:{canonical_key} registered to unexpected ID: {row.get('stable_id')}"
            )
    else:
        collision = [
            row
            for row in entries
            if isinstance(row, dict) and str(row.get("stable_id") or "") == stable_id
        ]
        if collision:
            raise SystemExit(
                f"stable ID collision for {stable_id}: "
                + json.dumps(collision, sort_keys=True)
            )
        entries.append(
            {
                "aliases": [],
                "canonical_key": canonical_key,
                "kind": "state",
                "stable_id": stable_id,
                "status": "active",
            }
        )
        stable_ids_path.write_text(
            json.dumps(stable_ids, indent=2) + chr(10),
            encoding="utf-8",
        )
        print(f"registered repair-introduced stable ID: {canonical_key} -> {stable_id}")

    print(
        "applied verified post-transform repair to explicit nested project "
        f"{project_rel} sha256={actual}"
    )
"""

NEW_RECONCILE_FUNCTION = '''def _reconcile_system_queue_origin_contract(here: Path) -> None:
    path = here.parent / "src" / "weall" / "runtime" / "system_tx_engine.py"
    text = path.read_text(encoding="utf-8")
    old = """def _is_system_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    return bool(info.get(\"system_only\") is True) if isinstance(info, dict) else False
"""
    repaired = """def _is_system_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    if not isinstance(info, dict):
        return False
    # Canon marks receipt/system-envelope transactions with origin=SYSTEM.
    # Some generated projections do not materialize a separate system_only flag,
    # so treating absence of that projection-only field as non-system corrupts
    # valid governance/system queue entries. Preserve an explicit system_only
    # marker when present, otherwise use the authoritative origin classification.
    if info.get(\"system_only\") is True:
        return True
    return str(info.get(\"origin\") or \"\").strip().upper() == \"SYSTEM\"
"""
    reconciled = """def _is_system_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    if not isinstance(info, dict):
        return False
    origin = _as_str(info.get(\"origin\") or \"\").strip().upper()
    return bool(info.get(\"system_only\") is True or origin == \"SYSTEM\")
"""

    old_count = text.count(old)
    repaired_count = text.count(repaired)
    reconciled_count = text.count(reconciled)
    known_count = old_count + repaired_count + reconciled_count
    if known_count != 1:
        raise SystemExit(
            "system queue origin contract shape mismatch: "
            f"old={old_count} repaired={repaired_count} reconciled={reconciled_count}"
        )
    if repaired_count == 1:
        print("system queue origin contract already reconciled by verified post-transform repair")
        return
    if reconciled_count == 1:
        print("system queue origin contract already reconciled")
        return

    updated = text.replace(old, reconciled, 1)
    compile(updated, str(path), "exec")
    path.write_text(updated, encoding="utf-8")
    print("reconciled SYSTEM queue authority with canonical origin semantics")
'''


def _run_original_patcher() -> None:
    blob = subprocess.check_output(
        ["git", "rev-parse", f"{ORIGINAL_COMMIT}:{ORIGINAL_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if blob != ORIGINAL_BLOB:
        raise SystemExit(
            f"known-good materialized-driver patcher blob drift: {blob} != {ORIGINAL_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{ORIGINAL_COMMIT}:{ORIGINAL_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_IMPL.write_bytes(source)
    try:
        namespace = runpy.run_path(
            str(TEMP_IMPL),
            run_name="r20_original_materialized_driver_patcher",
        )
        original_main = namespace.get("main")
        if not callable(original_main):
            raise SystemExit("known-good materialized-driver patcher has no callable main()")
        rc = original_main()
        if rc not in (None, 0):
            raise SystemExit(f"known-good materialized-driver patcher failed: {rc}")
    finally:
        TEMP_IMPL.unlink(missing_ok=True)


def _replace_bootstrap_function(name: str, replacement: str) -> None:
    text = BOOTSTRAP.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(BOOTSTRAP))
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1:
        raise SystemExit(f"{name} function count mismatch: expected 1, got {len(matches)}")
    node = matches[0]
    if node.end_lineno is None:
        raise SystemExit(f"{name} function has no end line")
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1 : node.end_lineno] = [replacement + "\n"]
    updated = "".join(lines)
    ast.parse(updated, filename=str(BOOTSTRAP))
    BOOTSTRAP.write_text(updated, encoding="utf-8")


def _bind_repair_scope() -> None:
    _replace_bootstrap_function("_apply_post_transform_repair", NEW_REPAIR_FUNCTION)
    _replace_bootstrap_function(
        "_reconcile_system_queue_origin_contract",
        NEW_RECONCILE_FUNCTION,
    )
    print(
        "bound post-transform repair to explicit nested project and made "
        "system queue reconciliation fail-closed/idempotent"
    )


def main() -> int:
    _run_original_patcher()
    _bind_repair_scope()
    if TEMP_IMPL.exists():
        raise SystemExit(f"transient patcher was not removed: {TEMP_IMPL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
