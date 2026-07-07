from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_observer_account_creation_reuses_prepared_browser_bootstrap_key() -> None:
    src = (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")
    keyfile_idx = src.index('--keyfile "${OBSERVER_KEYFILE}"')
    reuse_idx = src.index("--reuse-keyfile", keyfile_idx)
    tee_idx = src.index('tee "${GENERATED_DIR}/observer-account-register.json"', reuse_idx)

    assert keyfile_idx < reuse_idx < tee_idx


def test_observer_bootstrap_manifest_rewritten_after_registration() -> None:
    src = (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")
    registration_marker = 'tee "${GENERATED_DIR}/observer-account-register.json"'
    rewrite_marker = '_write_secret_and_manifest "${OBSERVER_ACCOUNT}" "${OBSERVER_KEYFILE}" "${OBSERVER_SECRET}" "${OBSERVER_MANIFEST}" "local-controlled-devnet-observer" "1"'
    frontend_marker = "Starting observer frontend"

    assert rewrite_marker in src
    registration_idx = src.index(registration_marker)
    rewrite_idx = src.index(rewrite_marker, registration_idx)
    assert registration_idx < rewrite_idx < src.index(frontend_marker)
    assert "same key material that\n# the observer account registration actually used" in src
    assert 'signature verification failed' in src
