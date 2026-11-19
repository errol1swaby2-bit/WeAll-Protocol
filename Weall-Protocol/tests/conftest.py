from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Both pytest entry points must resolve the same checkout-local modules.
# The console entry point does not automatically put the current working
# directory on sys.path, unlike python -m pytest. Review tests import the
# repository's scripts and tooling namespaces as well as the runtime.
ROOT = Path(__file__).resolve().parents[1]
REPO_SRC = ROOT / "src"
# Only the mutation harness sets this explicit, subprocess-local source root.
# Read it before the hermetic WEALL_* cleanup below. An ordinary pytest run
# must use the checkout, but a mutation run must never silently test it.
_MUTATION_SRC = os.environ.get("WEALL_PYTEST_MUTATION_SRC")
SRC = Path(_MUTATION_SRC).resolve(strict=True) if _MUTATION_SRC else REPO_SRC
if _MUTATION_SRC and (SRC == REPO_SRC.resolve() or not (SRC / "weall" / "__init__.py").is_file()):
    raise RuntimeError("invalid pytest mutation source overlay")

# Runtime source first, repository-local review namespaces second.
for _path in (str(ROOT), str(SRC)):
    if _path in sys.path:
        sys.path.remove(_path)
    sys.path.insert(0, _path)


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
    # Explicit test harness posture: production code must never infer pytest state.
    os.environ["WEALL_MODE"] = "test"
    # Runtime-mode tests frequently switch WEALL_MODE to prod to exercise
    # production validation/topology semantics.  That is not a mainnet crypto
    # activation.  Pin the hermetic suite to the reviewed closed-testnet crypto
    # posture unless a test explicitly overrides/deletes this variable.
    os.environ["WEALL_CRYPTO_MODE"] = "closed-testnet"
    os.environ["WEALL_API_BOOT_RUNTIME"] = "0"

from weall.tx.canon import ensure_tx_index_json  # noqa: E402

# Fail during conftest import (not a mutant test assertion) if the runtime
# resolves outside the requested source tree. An import/collection failure
# is classified as an invalid mutation by the assurance harness, never a kill.
for _module_name in ("weall", "weall.tx.canon"):
    _module_file = Path(sys.modules[_module_name].__file__).resolve()
    if not _module_file.is_relative_to(SRC.resolve()):
        raise RuntimeError(f"unexpected pytest runtime source: {_module_name}: {_module_file}")

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
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    monkeypatch.setenv("WEALL_API_BOOT_RUNTIME", "0")


@pytest.fixture
def valid_observer_genesis_artifacts(tmp_path: Path) -> dict[str, str]:
    """Isolated public-key-only fixture; never validates pinned prod readiness.

    Observer posture unit tests should exercise their shell contracts on a
    reproducibly generated *valid* candidate manifest. The tracked production
    genesis remains separately blocked until its authentic founder key and
    external ceremony evidence are accepted.
    """
    from weall.testing.sigtools import deterministic_mldsa_keypair

    founder_pubkey, _unused_test_seed = deterministic_mldsa_keypair(
        label="observer-authority-lock-valid-fixture"
    )
    genesis_path = tmp_path / "genesis.ledger.prod.test.json"
    manifest_path = tmp_path / "weall-genesis.test.json"
    tx_index_path = ROOT / "generated" / "tx_index.json"
    build = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_production_genesis_manifest.py"),
            "--chain-id",
            "weall-observer-posture-test",
            "--founding-account",
            "@observer-fixture-founder",
            "--founding-pubkey",
            founder_pubkey,
            "--authority-pubkey",
            "b" * 64,
            "--genesis-time",
            "1900000000",
            "--tx-index",
            str(tx_index_path),
            "--genesis-out",
            str(genesis_path),
            "--manifest-out",
            str(manifest_path),
        ],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert build.returncode == 0, build.stderr + build.stdout
    return {
        "WEALL_CHAIN_MANIFEST_PATH": str(manifest_path),
        "WEALL_GENESIS_LEDGER_PATH": str(genesis_path),
        "WEALL_TX_INDEX_PATH": str(tx_index_path),
    }
