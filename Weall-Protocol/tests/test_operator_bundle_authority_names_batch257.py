from __future__ import annotations

import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_node_operator_onboarding_bundle.py"


def _load_verify_module():
    spec = importlib.util.spec_from_file_location(
        "verify_node_operator_onboarding_bundle",
        VERIFY_SCRIPT,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_bundle_verifier_prefers_authority_over_legacy_oracle() -> None:
    mod = _load_verify_module()

    assert hasattr(mod, "_authority"), (
        "verify_node_operator_onboarding_bundle.py must expose _authority() "
        "instead of the old _oracle() helper."
    )

    bundle = {
        "authority": {
            "url": "http://authority.example",
            "profile": "production",
            "pubkeys": ["authority-pubkey"],
        },
        "oracle": {
            "url": "http://legacy-oracle.example",
            "profile": "legacy",
            "pubkeys": ["legacy-oracle-pubkey"],
        },
    }

    authority = mod._authority(bundle)

    assert authority["url"] == "http://authority.example"
    assert authority["profile"] == "production"
    assert authority["pubkeys"] == ["authority-pubkey"]


def test_operator_bundle_verifier_supports_legacy_oracle_fallback_read_only() -> None:
    mod = _load_verify_module()

    bundle = {
        "oracle": {
            "url": "http://legacy-oracle.example",
            "profile": "legacy",
            "pubkeys": ["legacy-oracle-pubkey"],
        }
    }

    authority = mod._authority(bundle)

    assert authority["url"] == "http://legacy-oracle.example"
    assert authority["profile"] == "legacy"
    assert authority["pubkeys"] == ["legacy-oracle-pubkey"]


def test_operator_bundle_scripts_do_not_emit_old_public_oracle_env_name() -> None:
    verify_source = VERIFY_SCRIPT.read_text(encoding="utf-8")
    build_source = BUILD_SCRIPT.read_text(encoding="utf-8")

    assert "WEALL_AUTHORITY_PUBKEYS" in verify_source
    assert "WEALL_ORACLE_AUTHORITY_PUBKEYS" not in verify_source
    assert '"authority"' in build_source
