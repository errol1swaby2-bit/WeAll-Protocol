#!/usr/bin/env python3
from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

MIN_PYTHON = (3, 12)
REQUIRED_PACKAGES = {
    "cryptography": (48, 0, 1),
    "pytest": (8, 0, 0),
    "fastapi": (0, 139, 2),
}


def version_tuple(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in raw.replace("-", ".").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def command_version(command: str, *args: str) -> str:
    executable = shutil.which(command)
    if not executable:
        return ""
    result = subprocess.run(
        [executable, *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def main() -> int:
    failures: list[str] = []
    report: dict[str, object] = {
        "schema": "weall.m3.dependency-preflight.v1",
        "python": platform.python_version(),
        "packages": {},
        "commands": {},
    }

    if sys.version_info[:2] < MIN_PYTHON:
        failures.append(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; found {platform.python_version()}"
        )

    package_report: dict[str, object] = {}
    for package, minimum in REQUIRED_PACKAGES.items():
        try:
            installed = metadata.version(package)
        except metadata.PackageNotFoundError:
            installed = ""
        ok = bool(installed) and version_tuple(installed) >= minimum
        package_report[package] = {
            "installed": installed or None,
            "minimum": ".".join(str(x) for x in minimum),
            "ok": ok,
        }
        if not ok:
            failures.append(
                f"{package}>={'.'.join(str(x) for x in minimum)} is required; found {installed or 'missing'}"
            )
    report["packages"] = package_report

    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401

        report["mldsa_import"] = True
    except Exception as exc:  # pragma: no cover - environment dependent
        report["mldsa_import"] = False
        report["mldsa_error"] = f"{type(exc).__name__}: {exc}"
        failures.append("cryptography ML-DSA support is unavailable")

    node = command_version("node", "--version")
    npm = command_version("npm", "--version")
    report["commands"] = {"node": node or None, "npm": npm or None}
    if not node:
        failures.append("node is missing (Node.js >=20.19.0 required for frontend closure)")
    elif version_tuple(node.lstrip("v")) < (20, 19, 0):
        failures.append(f"Node.js >=20.19.0 is required; found {node}")
    if not npm:
        failures.append("npm is missing (npm >=10 required for frontend closure)")
    elif version_tuple(npm) < (10, 0, 0):
        failures.append(f"npm >=10 is required; found {npm}")

    report["ok"] = not failures
    report["failures"] = failures
    print(json.dumps(report, indent=2, sort_keys=True))
    if failures:
        print(
            "\nM3 dependency preflight failed. Run scripts/bootstrap_m3_environment.sh "
            "from the repository root. For offline environments, set WEALL_WHEELHOUSE "
            "to a directory containing the locked Python wheels.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
