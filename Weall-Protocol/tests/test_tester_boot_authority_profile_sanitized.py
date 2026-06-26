from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tester_node_boot_clears_bundle_authority_profile_after_env_source_batch471() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    source_index = script.index('source "${ENV_FILE}"')
    unset_index = script.index("unset WEALL_AUTHORITY_PROFILE")

    assert source_index < unset_index
    assert "tester node boot intentionally clears bundle authority profile" in script


def test_tester_node_boot_preserves_observer_safety_flags_batch471() -> None:
    script = (ROOT / "scripts" / "weall_tester_node.sh").read_text(encoding="utf-8")

    assert "WEALL_OBSERVER_MODE=1" in script
    assert "WEALL_VALIDATOR_SIGNING_ENABLED=0" in script
    assert "WEALL_BFT_ENABLED=0" in script
