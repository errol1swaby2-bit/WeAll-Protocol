from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _script(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def test_bootstrap_tier3_cli_payload_matches_strict_schema_batch230() -> None:
    """The devnet bootstrap helper must not emit fields rejected by tx_schema.

    POH_BOOTSTRAP_TIER3_GRANT is intentionally strict at API admission.  The
    runtime apply path still tolerates a legacy pubkey field for historical
    compatibility, but public tx submission validates against
    PohBootstrapTier3GrantPayload, which only accepts account_id plus optional
    accepted/note fields.  The controlled-devnet reviewer setup flow must use
    that strict public shape.
    """

    tree = ast.parse(_script("scripts/devnet_tx.py"))
    found_payload = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "cmd_bootstrap_tier3":
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Assign):
                is_payload = any(
                    isinstance(target, ast.Name) and target.id == "payload" for target in inner.targets
                )
                value = inner.value
            elif isinstance(inner, ast.AnnAssign):
                is_payload = isinstance(inner.target, ast.Name) and inner.target.id == "payload"
                value = inner.value
            else:
                continue
            if not is_payload:
                continue
            found_payload = True
            assert isinstance(value, ast.Dict)
            keys = {
                key.value
                for key in value.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            assert keys == {"account_id"}
    assert found_payload


def test_tier3_reviewer_prepare_still_uses_normal_signed_submit_batch230() -> None:
    combined = "\n".join(
        _script(rel)
        for rel in [
            "scripts/devnet_prepare_tier3_jurors.sh",
            "scripts/devnet_bootstrap_tier3.sh",
            "scripts/devnet_tx.py",
        ]
    )
    assert "POH_BOOTSTRAP_TIER3_GRANT" in combined
    assert "/v1/tx/submit" in combined
    assert "/v1/dev/demo-seed" not in combined
    assert "demo-seed" not in combined
