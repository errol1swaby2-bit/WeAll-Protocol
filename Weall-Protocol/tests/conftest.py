from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure local "src/" takes precedence over any globally-installed "weall" package.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

src_str = str(SRC)
if src_str not in sys.path:
    sys.path.insert(0, src_str)


# Pytest must be hermetic. Operator/rehearsal shells often export WEALL_*
# variables (prod mode, BFT, networking, block loops, key paths). Letting those
# leak into unrelated unit tests turns local persistence/apply fixtures into
# production topology boots and can mask real regressions behind environment
# posture errors. Tests that need WEALL_* state should set it explicitly with
# monkeypatch inside the test.
_KEEP_EXTERNAL_WEALL_ENV = os.environ.get("WEALL_PYTEST_KEEP_EXTERNAL_ENV") == "1"
if not _KEEP_EXTERNAL_WEALL_ENV:
    for _name in list(os.environ):
        if _name.startswith("WEALL_"):
            os.environ.pop(_name, None)

from weall.tx.canon import ensure_tx_index_json  # noqa: E402

# Make test collection resilient on a fresh clone / first boot.
# If the generated tx index is missing or stale, rebuild it before tests import
# files that read generated/tx_index.json at module scope.
ensure_tx_index_json(
    spec_path=ROOT / "specs" / "tx_canon" / "tx_canon.yaml",
    out_path=ROOT / "generated" / "tx_index.json",
)


@pytest.fixture(autouse=True)
def _weall_pytest_external_env_isolation(monkeypatch: pytest.MonkeyPatch):
    """Prevent operator shell WEALL_* exports from contaminating tests.

    The fixture also isolates tests from each other when a test sets WEALL_*
    without using monkeypatch.  Tests that intentionally need inherited operator
    environment can opt out by running with WEALL_PYTEST_KEEP_EXTERNAL_ENV=1.
    """

    if _KEEP_EXTERNAL_WEALL_ENV:
        return
    for name in list(os.environ):
        if name.startswith("WEALL_"):
            monkeypatch.delenv(name, raising=False)
