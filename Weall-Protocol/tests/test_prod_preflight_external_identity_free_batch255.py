from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def join(*parts: str) -> str:
    return "".join(parts)


def test_prod_preflight_does_not_call_removed_external_identity_preflight() -> None:
    for rel in [
        "scripts/prod_node_preflight.sh",
        "scripts/prod_node_operator_from_bundle_preflight.sh",
    ]:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert join("prod_", "poh_", "email_", "oracle", "_operator_preflight.sh") not in text
        assert join("prod_", "email_", "oracle") not in text
        assert join("poh/", "email") not in text


def test_removed_external_identity_operator_scripts_are_absent() -> None:
    for rel in [
        join("scripts/prod_", "email_", "oracle_start.sh"),
        join("scripts/prod_", "email_", "oracle_verify.sh"),
        join("scripts/rollback_testnet_", "email_", "rate_limit.sh"),
    ]:
        assert not (ROOT / rel).exists(), rel
