#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def command(args: list[str], *, cwd: Path = ROOT) -> dict[str, Any]:
    proc = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )
    return {
        "argv": args,
        "returncode": proc.returncode,
        "output": proc.stdout.strip(),
    }


def version(name: str, args: list[str]) -> dict[str, Any]:
    path = shutil.which(name)
    if not path:
        return {"available": False}
    result = command(args)
    return {"available": True, "path": path, **result}


def file_binding(relative: str) -> dict[str, Any]:
    path = ROOT / relative
    if not path.is_file():
        return {"path": relative, "present": False}
    return {
        "path": relative,
        "present": True,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--freeze-commit", default="HEAD")
    args = parser.parse_args()

    freeze = command(["git", "rev-parse", f"{args.freeze_commit}^{{commit}}"])
    if freeze["returncode"] != 0:
        raise SystemExit(f"unable_to_resolve_freeze:{freeze['output']}")
    freeze_commit = freeze["output"]
    tree = command(["git", "rev-parse", f"{freeze_commit}^{{tree}}"]) ["output"]

    pip_freeze = command([sys.executable, "-m", "pip", "freeze", "--all"])
    os_packages: dict[str, Any]
    if shutil.which("dpkg-query"):
        os_packages = command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    elif shutil.which("rpm"):
        os_packages = command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    else:
        os_packages = {"argv": [], "returncode": 127, "output": "unsupported_package_manager"}

    value = {
        "schema": "weall.m1_m3.reproducible_environment.v1",
        "implementation_freeze_commit": freeze_commit,
        "implementation_tree": tree,
        "platform": {
            "python": sys.version,
            "python_executable": sys.executable,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "tool_versions": {
            "git": version("git", ["git", "--version"]),
            "node": version("node", ["node", "--version"]),
            "npm": version("npm", ["npm", "--version"]),
            "playwright": version(
                "npx", ["npx", "--no-install", "playwright", "--version"]
            ),
            "docker": version("docker", ["docker", "--version"]),
            "gpg": version("gpg", ["gpg", "--version"]),
        },
        "dependency_bindings": [
            file_binding("Weall-Protocol/requirements.lock"),
            file_binding("Weall-Protocol/requirements-dev.lock"),
            file_binding("web/package-lock.json"),
            file_binding("docker/Dockerfile.m1-m3-closure"),
            file_binding(
                "Weall-Protocol/configs/consensus_profiles/weall-m1-m3-production-v1.json"
            ),
        ],
        "pip_freeze": sorted(
            line for line in pip_freeze["output"].splitlines() if line.strip()
        ),
        "os_packages": sorted(
            line for line in os_packages["output"].splitlines() if line.strip()
        ),
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"OK: wrote reproducible environment manifest to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
