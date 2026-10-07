from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "Weall-Protocol"


def _assert_bootstrap_precedes_activation(text: str) -> None:
    marker = "source .venv/bin/activate"
    activate = text.index(marker)
    create = text.rfind("python3 -m venv .venv", 0, activate)
    locked = text.find("python -m pip install --require-hashes -r requirements-dev.lock", activate)
    editable = text.find("python -m pip install -e . --no-deps", activate)
    assert create >= 0
    assert locked > activate
    assert editable > locked


def test_primary_verification_paths_bootstrap_fresh_checkout() -> None:
    _assert_bootstrap_precedes_activation((ROOT / "README.md").read_text(encoding="utf-8"))
    _assert_bootstrap_precedes_activation((BACKEND / "README.md").read_text(encoding="utf-8"))
