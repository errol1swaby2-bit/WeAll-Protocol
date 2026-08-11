from __future__ import annotations

import ast
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
OUTER = BACKEND.parent


def test_production_source_contains_no_assert_statements() -> None:
    violations: list[str] = []
    for path in sorted((BACKEND / "src" / "weall").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                violations.append(f"{path.relative_to(BACKEND)}:{node.lineno}")
    assert violations == [], "production assert statements remain: " + ", ".join(violations)


def test_m3_complete_closure_has_no_bare_python_execution() -> None:
    path = OUTER / "scripts" / "run_m3_complete_closure.sh"
    text = path.read_text(encoding="utf-8")
    bare = [
        f"{idx}:{line}"
        for idx, line in enumerate(text.splitlines(), 1)
        if re.search(r"(^|[;&|() \t])python([ \t]|$)", line)
    ]
    assert bare == [], "bare python execution remains: " + " | ".join(bare)


def test_pof_metadata_helper_is_not_named_as_a_cid_placeholder() -> None:
    apply_source = (BACKEND / "src" / "weall" / "poh" / "apply.py").read_text(encoding="utf-8")
    finalize_source = (BACKEND / "src" / "weall" / "poh" / "finalize.py").read_text(
        encoding="utf-8"
    )
    assert "canonical_metadata_cid_placeholder" not in apply_source
    assert "canonical_metadata_cid_placeholder" not in finalize_source
    assert "canonical_metadata_reference" in apply_source
    assert "canonical_metadata_reference" in finalize_source
