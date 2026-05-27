from __future__ import annotations

import json
import shlex
from pathlib import Path


def test_frontend_package_script_targets_exist_batch436() -> None:
    repo = Path(__file__).resolve().parents[2]
    web = repo / "web"
    package_json = web / "package.json"
    assert package_json.is_file(), "outer web/package.json must be present in release/testnet bundle"

    pkg = json.loads(package_json.read_text(encoding="utf-8"))
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    missing: list[str] = []
    for name, command in sorted(scripts.items()):
        if not isinstance(command, str):
            continue
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        for token in tokens:
            if not token.startswith("scripts/"):
                continue
            if not token.endswith((".js", ".mjs", ".cjs", ".sh")):
                continue
            if not (web / token).is_file():
                missing.append(f"{name}:{token}")
    assert missing == []
