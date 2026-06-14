#!/usr/bin/env bash
set -euo pipefail

# Build and verify a clean, shareable WeAll release export from a possibly dirty
# working tree. Unlike Weall-Protocol/scripts/release_package.sh, this wrapper
# stages the full outer project layout (backend + web + top-level scripts) first,
# cleans the staged copy, verifies it, and only then writes the archive. The
# source working tree is never mutated.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_ROOT="$ROOT/Weall-Protocol"
WEB_ROOT="$ROOT/web"
OUT_DIR="${OUT_DIR:-$ROOT/release}"
STAMP="${WEALL_RELEASE_STAMP:-$(date +%Y-%m-%d_%H-%M-%S)}"
STAGING_PARENT="${WEALL_RELEASE_STAGING:-}"
KEEP_STAGING=0
VERIFY_ONLY=0
ARCHIVE_NAME="${ARCHIVE_NAME:-WeAll-Protocol-clean-release-${STAMP}.zip}"

usage() {
  cat >&2 <<'USAGE'
usage: scripts/build_clean_release_export.sh [--verify-only] [--keep-staging]

Environment:
  OUT_DIR                 Directory for release zip. Default: ./release
  WEALL_RELEASE_STAMP     Deterministic archive suffix for tests.
  WEALL_RELEASE_STAGING   Optional parent directory for staged copy.
  ARCHIVE_NAME            Optional archive filename.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    --keep-staging)
      KEEP_STAGING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

log() {
  printf '[release-export] %s\n' "$*"
}

die() {
  printf '[release-export] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

[[ -d "$BACKEND_ROOT" ]] || die "missing backend tree: $BACKEND_ROOT"
[[ -f "$BACKEND_ROOT/scripts/verify_release_tree.sh" ]] || die "missing backend release verifier"
[[ -f "$BACKEND_ROOT/scripts/clean_release_artifacts.sh" ]] || die "missing backend release cleanup script"
[[ -d "$WEB_ROOT" ]] || die "missing frontend tree: $WEB_ROOT"

require_cmd python3
if [[ "$VERIFY_ONLY" != "1" ]]; then
  require_cmd zip
fi

if [[ -n "$STAGING_PARENT" ]]; then
  mkdir -p "$STAGING_PARENT"
  STAGING_PARENT="$(cd "$STAGING_PARENT" && pwd)"
else
  STAGING_PARENT="$(mktemp -d -t weall-release-export.XXXXXX)"
fi
STAGED_ROOT="$STAGING_PARENT/WeAll-Protocol"
ARCHIVE_PATH="$OUT_DIR/$ARCHIVE_NAME"

cleanup_staging() {
  if [[ "$KEEP_STAGING" == "1" ]]; then
    log "kept staged tree: $STAGED_ROOT"
  elif [[ -n "${STAGING_PARENT:-}" && -d "$STAGING_PARENT" ]]; then
    rm -rf -- "$STAGING_PARENT"
  fi
}
trap cleanup_staging EXIT

log "source: $ROOT"
log "staging: $STAGED_ROOT"
rm -rf -- "$STAGED_ROOT"
mkdir -p "$STAGED_ROOT"

# Copy through Python rather than rsync so the gate works on fresh machines that
# may not have rsync installed. Ignore release-forbidden artifacts both for speed
# and defense in depth; the staged cleanup/verifier still run afterward.
python3 - "$ROOT" "$STAGED_ROOT" <<'PY'
from __future__ import annotations

import shutil
import sys
from pathlib import Path

src = Path(sys.argv[1]).resolve()
dst = Path(sys.argv[2]).resolve()

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pyright",
    ".tox",
    ".nox",
    ".provider-cli",
    ".weall-devnet",
    ".weall",
    "data",
    "data_local",
    "data.backup.test",
    "data.before-restore",
    "tmp",
    "dev",
    "playwright-report",
    "test-results",
}

SKIP_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".aux.sqlite",
    ".db.bft_journal.jsonl",
    ".tsbuildinfo",
    ".rej",
    ".orig",
    ".log",
    ".tmp",
    ".pid",
)

SKIP_FILE_NAMES = {
    ".env",
    ".env.local",
    "demo_bootstrap_result.json",
    "demo_bootstrap_secret.json",
}

SKIP_GLOB_PARTS = (
    ".aux_helper_lanes",
    ".pytest-b",
)

SECRET_ALLOW = {".gitignore", "README.md", "README"}


def should_skip(path: Path, *, is_dir: bool) -> bool:
    rel = path.relative_to(src)
    parts = rel.parts
    name = path.name

    if name in SKIP_FILE_NAMES:
        return True
    if any(part in SKIP_DIR_NAMES for part in parts):
        return True
    if any(marker in name for marker in SKIP_GLOB_PARTS):
        return True
    if name.endswith(SKIP_SUFFIXES):
        return True
    if "secrets" in parts:
        # Preserve only placeholder docs if they exist. Never export local keys,
        # even public-key sidecars; the manifest/bundle is the public authority.
        if name in SECRET_ALLOW and not is_dir:
            return False
        return True
    return False


def copy_tree(current_src: Path, current_dst: Path) -> None:
    current_dst.mkdir(parents=True, exist_ok=True)
    for child in current_src.iterdir():
        if should_skip(child, is_dir=child.is_dir()):
            continue
        target = current_dst / child.name
        if child.is_dir():
            copy_tree(child, target)
        elif child.is_symlink():
            # Avoid exporting machine-local symlink targets. Copy file content for
            # symlinked files only if the target resolves inside the repo.
            resolved = child.resolve()
            if not str(resolved).startswith(str(src)) or not resolved.is_file():
                continue
            shutil.copy2(resolved, target)
        else:
            shutil.copy2(child, target)

copy_tree(src, dst)
PY

STAGED_BACKEND="$STAGED_ROOT/Weall-Protocol"
STAGED_WEB="$STAGED_ROOT/web"
[[ -d "$STAGED_BACKEND" ]] || die "staged backend tree missing"
[[ -d "$STAGED_WEB" ]] || die "staged frontend tree missing"

log "cleaning staged tree"
(
  cd "$STAGED_BACKEND"
  bash scripts/clean_release_artifacts.sh
)

log "verifying staged backend release tree"
(
  cd "$STAGED_BACKEND"
  bash scripts/verify_release_tree.sh
  bash scripts/secret_guard.sh
  bash scripts/verify_release_dependencies.sh
)

log "writing fresh audit metadata into staged export"
python3 - "$ROOT" "$STAGED_ROOT" <<'PY'
from __future__ import annotations

import datetime as _dt
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
staged = Path(sys.argv[2]).resolve()
meta = staged / "audit-metadata"
meta.mkdir(parents=True, exist_ok=True)

def git(args: list[str]) -> str:
    proc = subprocess.run(["git", *args], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""

tracked = git(["ls-files"]).splitlines()
included = []
for rel in tracked:
    if (staged / rel).exists():
        included.append(rel)

now = _dt.datetime.now(_dt.timezone.utc).isoformat()
metadata = [
    "schema=weall.audit_metadata.v1",
    f"created_at_utc={now}",
    f"source_repo_root={root}",
    f"git_head={git(['rev-parse', 'HEAD'])}",
    f"git_branch={git(['branch', '--show-current'])}",
    "",
    "latest_commit:",
    git(["log", "--oneline", "-1"]),
    "",
    "git_status_short:",
    git(["status", "--short", "--untracked-files=all"]) or "<clean>",
    "",
    f"tracked_file_count={len(tracked)}",
    f"included_tracked_file_count={len(included)}",
    "metadata_generation=build_clean_release_export.sh",
    "truth_boundary=export metadata binds archive contents to source checkout; public beta/mainnet readiness is not claimed",
]
(meta / "AUDIT_METADATA.txt").write_text("\n".join(metadata) + "\n", encoding="utf-8")
(meta / "GIT_TRACKED_FILES.txt").write_text("\n".join(tracked) + "\n", encoding="utf-8")
(meta / "AUDIT_INCLUDED_PATHS.txt").write_text("\n".join(included) + "\n", encoding="utf-8")
PY

if find "$STAGED_ROOT" -name '*.rej' -o -name '*.orig' -o -name '*.tsbuildinfo' | grep -q .; then
  find "$STAGED_ROOT" -name '*.rej' -o -name '*.orig' -o -name '*.tsbuildinfo'
  die "staged export contains reject/orig/build-info artifacts"
fi

if find "$STAGED_ROOT" \( -name node_modules -o -name dist -o -name '.pytest_cache' -o -name '__pycache__' -o -name '.weall-devnet' -o -name '.weall' -o -name data -o -name '*.aux_helper_lanes' \) -print | grep -q .; then
  find "$STAGED_ROOT" \( -name node_modules -o -name dist -o -name '.pytest_cache' -o -name '__pycache__' -o -name '.weall-devnet' -o -name '.weall' -o -name data -o -name '*.aux_helper_lanes' \) -print
  die "staged export contains release-forbidden directories"
fi

if grep -R "packages.applied-caas-gateway" "$STAGED_WEB/package-lock.json" >/dev/null 2>&1; then
  die "staged package-lock.json contains sandbox-internal npm registry URLs"
fi

if [[ "$VERIFY_ONLY" == "1" ]]; then
  log "verify-only gate passed"
  exit 0
fi

mkdir -p "$OUT_DIR"
rm -f -- "$ARCHIVE_PATH"
log "writing archive: $ARCHIVE_PATH"
(
  cd "$STAGING_PARENT"
  zip -qr "$ARCHIVE_PATH" "WeAll-Protocol"
)

log "verifying archive contents"
python3 - "$ARCHIVE_PATH" <<'PY'
from __future__ import annotations

import sys
import zipfile

archive = sys.argv[1]
forbidden_names = (
    "/node_modules/",
    "/dist/",
    "/.pytest_cache/",
    "/__pycache__/",
    "/.weall-devnet/",
    "/.weall/",
    "/data/",
    ".tsbuildinfo",
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".aux.sqlite",
    ".db.bft_journal.jsonl",
    ".rej",
    ".orig",
)
with zipfile.ZipFile(archive) as zf:
    names = zf.namelist()
    bad = [name for name in names if any(marker in name for marker in forbidden_names)]
    if bad:
        for name in bad[:50]:
            print(name)
        raise SystemExit("archive contains release-forbidden artifacts")
    required = [
        "WeAll-Protocol/Weall-Protocol/generated/tx_index.json",
        "WeAll-Protocol/Weall-Protocol/generated/helper_contract_map.json",
        "WeAll-Protocol/Weall-Protocol/generated/tx_contract_map.json",
        "WeAll-Protocol/web/package-lock.json",
        "WeAll-Protocol/scripts/fresh_clone_smoke.sh",
    ]
    missing = [name for name in required if name not in names]
    if missing:
        for name in missing:
            print(f"missing {name}")
        raise SystemExit("archive missing required files")
print("archive release gate passed")
PY

log "release export gate passed"
log "wrote $ARCHIVE_PATH"
