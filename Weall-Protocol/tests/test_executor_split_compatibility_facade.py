from __future__ import annotations

import ast
from pathlib import Path

from weall.runtime import executor

ROOT = Path(__file__).resolve().parents[1]


def test_executor_split_imports_resolve_through_compatibility_facade() -> None:
    runtime_root = ROOT / "src" / "weall" / "runtime"
    checked: set[str] = set()

    for path in sorted(runtime_root.rglob("*.py")):
        if path.name == "executor.py":
            continue

        tree = ast.parse(path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module != "weall.runtime.executor":
                continue

            for alias in node.names:
                checked.add(alias.name)
                assert getattr(executor, alias.name) is not None, (
                    f"{path.relative_to(ROOT)} imports missing executor "
                    f"facade symbol {alias.name!r}"
                )

    assert checked


def test_executor_monkeypatch_compatibility_hooks_are_exported() -> None:
    required = (
        "apply_tx_atomic_meta",
        "schedule_poh_tier2_system_txs",
        "system_tx_emitter",
    )

    for name in required:
        assert getattr(executor, name) is not None
