from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.failpoints import maybe_trigger_failpoint

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "relative_path",
    [
        "src/weall/runtime/runtime_posture.py",
        "src/weall/runtime/block_builder.py",
        "src/weall/runtime/block_replay.py",
        "src/weall/runtime/chain_config.py",
        "src/weall/runtime/chain_manifest.py",
        "src/weall/api/security.py",
        "src/weall/api/public_seed_registry.py",
    ],
)
def test_security_and_consensus_sources_do_not_branch_on_pytest(relative_path: str) -> None:
    text = (ROOT / relative_path).read_text(encoding="utf-8")
    assert "PYTEST_CURRENT_TEST" not in text


def test_runtime_helper_executor_is_not_shipped_as_production_runtime() -> None:
    assert not (ROOT / "src/weall/runtime/helper_executor.py").exists()
    assert (ROOT / "src/weall/testing/helper_executor.py").is_file()


def test_production_posture_disables_test_failpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_TEST_FAILPOINT", "integrity_probe")
    monkeypatch.setenv("WEALL_TEST_FAILPOINT_ACTION", "exit")
    # If production failpoints were active this call would os._exit().
    maybe_trigger_failpoint("integrity_probe")


def test_testing_helper_rejects_synthetic_secret_material() -> None:
    from weall.testing.helper_executor import HelperExecutor

    with pytest.raises(ValueError, match="32-byte hex ML-DSA seed"):
        HelperExecutor({"h1": "secret"})
