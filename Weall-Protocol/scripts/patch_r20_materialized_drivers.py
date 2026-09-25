#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMPL = HERE / "patch_r20_materialized_drivers_impl.py"
BOOTSTRAP = HERE / "bootstrap_r20_remediation.py"

OLD = '''def _apply_post_transform_repair(here: Path) -> None:
    payload_path = here / "r20_post_transform_repair.patch.gz.b64"
    encoded = payload_path.read_text(encoding="ascii").strip()
    raw = gzip.decompress(base64.b64decode(encoded))
    actual = hashlib.sha256(raw).hexdigest()
    if actual != POST_TRANSFORM_REPAIR_SHA256:
        raise SystemExit(
            f"post-transform repair digest mismatch: {actual} != {POST_TRANSFORM_REPAIR_SHA256}"
        )
    patch_path = here.parent / "generated" / "r20_post_transform_repair.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_bytes(raw)
    try:
        subprocess.run(
            ["git", "apply", "--check", str(patch_path)],
            cwd=here.parent,
            check=True,
        )
        subprocess.run(
            ["git", "apply", str(patch_path)],
            cwd=here.parent,
            check=True,
        )
    finally:
        patch_path.unlink(missing_ok=True)
    print(f"applied verified post-transform repair sha256={actual}")
'''

NEW = '''def _apply_post_transform_repair(here: Path) -> None:
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
    apply_cmd = ["git", "apply", f"--directory={project_rel}", str(patch_path)]
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


def main() -> int:
    namespace = runpy.run_path(str(IMPL), run_name="r20_materialized_driver_impl")
    impl_main = namespace.get("main")
    if not callable(impl_main):
        raise SystemExit("temporary r20 patcher implementation has no callable main()")
    rc = impl_main()
    if rc not in (None, 0):
        raise SystemExit(f"temporary r20 patcher implementation failed: {rc}")

    text = BOOTSTRAP.read_text(encoding="utf-8")
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(f"post-transform repair function anchor mismatch: {count}")
    updated = text.replace(OLD, NEW, 1)
    compile(updated, str(BOOTSTRAP), "exec")
    BOOTSTRAP.write_text(updated, encoding="utf-8")
    IMPL.unlink()
    print("bound post-transform repair to explicit nested project after audited bootstrap materialization")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
