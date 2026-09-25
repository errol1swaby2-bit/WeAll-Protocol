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

NEW_REPAIR_FUNCTION = '''def _apply_post_transform_repair(here: Path) -> None:
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

    print(
        "applied verified post-transform repair to explicit nested project "
        f"{project_rel} sha256={actual}"
    )
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
        namespace = runpy.run_path(str(TEMP_IMPL), run_name="r20_original_materialized_driver_patcher")
        original_main = namespace.get("main")
        if not callable(original_main):
            raise SystemExit("known-good materialized-driver patcher has no callable main()")
        rc = original_main()
        if rc not in (None, 0):
            raise SystemExit(f"known-good materialized-driver patcher failed: {rc}")
    finally:
        TEMP_IMPL.unlink(missing_ok=True)


def _bind_repair_scope() -> None:
    text = BOOTSTRAP.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(BOOTSTRAP))
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_apply_post_transform_repair"
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"post-transform repair function count mismatch: expected 1, got {len(matches)}"
        )
    node = matches[0]
    if node.end_lineno is None:
        raise SystemExit("post-transform repair function has no end line")
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1 : node.end_lineno] = [NEW_REPAIR_FUNCTION + "\n"]
    updated = "".join(lines)
    ast.parse(updated, filename=str(BOOTSTRAP))
    BOOTSTRAP.write_text(updated, encoding="utf-8")
    print("bound post-transform repair to explicit nested project after audited bootstrap materialization")


def main() -> int:
    _run_original_patcher()
    _bind_repair_scope()
    if TEMP_IMPL.exists():
        raise SystemExit(f"transient patcher was not removed: {TEMP_IMPL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
