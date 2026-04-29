from __future__ import annotations

import ast
from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, *, node_id: str, chain_id: str) -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / f"{node_id.strip('@')}.db")
    return WeAllExecutor(
        db_path=db_path, node_id=node_id, chain_id=chain_id, tx_index_path=tx_index_path
    )


def test_genesis_bootstrap_reputation_env_uses_integer_units(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    acct = "@bootstrap"
    pub = "ed25519:bootstrap"

    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_REPUTATION", "2.5")

    ex = _make_executor(tmp_path, node_id=acct, chain_id="guardrails-bootstrap")
    acct_rec = ex.read_state()["accounts"][acct]
    assert int(acct_rec["reputation_milli"]) == 2500


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST | None = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
    return None


def _forbidden_hits(path: Path) -> list[tuple[int, str, str]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    lines = source.splitlines()
    hits: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name is None:
            continue
        line = lines[node.lineno - 1].strip()
        if name in {"time.time", "datetime.now", "datetime.utcnow", "datetime.today"}:
            hits.append((node.lineno, name, line))
            continue
        if name == "float":
            hits.append((node.lineno, name, line))
            continue
        if name.startswith("random."):
            hits.append((node.lineno, name, line))
            continue
        if name in {"uuid.uuid1", "uuid.uuid4"}:
            hits.append((node.lineno, name, line))
            continue
    return hits


def test_consensus_critical_paths_do_not_reintroduce_nondeterministic_calls() -> None:
    root = _repo_root()
    critical_paths = [
        root / "src" / "weall" / "runtime" / "domain_dispatch.py",
        root / "src" / "weall" / "runtime" / "executor.py",
        root / "src" / "weall" / "runtime" / "tx_admission.py",
        root / "src" / "weall" / "runtime" / "poh" / "juror_select.py",
        root / "src" / "weall" / "runtime" / "poh" / "tier2_scheduler.py",
        root / "src" / "weall" / "runtime" / "poh" / "tier3_scheduler.py",
    ]
    critical_paths.extend(sorted((root / "src" / "weall" / "runtime" / "apply").glob("*.py")))

    allowed_snippets = {
        (root / "src" / "weall" / "runtime" / "executor.py").resolve(): {
            "return int(time.time() * 1000)",
        },
    }

    unexpected: list[str] = []
    for path in critical_paths:
        hits = _forbidden_hits(path)
        allowed = allowed_snippets.get(path.resolve(), set())
        for lineno, name, line in hits:
            if line in allowed:
                continue
            unexpected.append(f"{path.relative_to(root)}:{lineno}: {name}: {line}")

    assert not unexpected, "\n".join(unexpected)
