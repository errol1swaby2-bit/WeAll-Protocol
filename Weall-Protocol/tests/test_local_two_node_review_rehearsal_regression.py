"""Regression gates for defects reproduced in the October two-node PoH rehearsal.

These source/contract checks complement (not replace) two-browser E2E and
real-node acceptance/decryption tests. No private keys or proof video fixtures.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web" / "src"


def _backend(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _frontend(path: str) -> str:
    return (WEB / path).read_text(encoding="utf-8")


def test_local_rehearsal_launcher_has_safe_cryptographic_preflight() -> None:
    path = ROOT / "scripts/devnet_local_two_frontend_rehearsal.sh"
    completed = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    text = path.read_text(encoding="utf-8")
    assert "len(seed) != 32 or len(pub) != 1952" in text
    assert "base64.b64encode(seed).decode('ascii')" in text
    assert "base64.b64encode(seed + pub)" not in text
    assert text.count("export WEALL_MODE=controlled_devnet") == 2
    assert 'RESET="${WEALL_LOCAL_REHEARSAL_RESET:-0}"' in text
    assert 'generate_m2_actor_keys.mjs" "${GENESIS_KEYFILE}"' in text
    assert 'generate_m2_actor_keys.mjs" "${OBSERVER_KEYFILE}"' in text
    assert 'bash scripts/devnet_prepare_live_jurors.sh' in text
    assert text.index('bash scripts/devnet_prepare_live_jurors.sh') < text.index('==> Booting observer backend')
    assert "evidence_kem_public_key_b64" in text
    assert "evidence_kem_secret_key_b64" in text


def test_client_preserves_browser_headers_and_multipart_boundary() -> None:
    api = _frontend("api/weall.ts")
    assert "new Headers(init.headers)" in api
    assert 'headers.set("Accept", "application/json")' in api
    assert '!(init.body instanceof FormData)' in api
    assert "headers.set(\"Content-Type\", \"application/json\")" in api
    assert "...(init.headers || {})" not in api


def test_browser_receives_reviewer_secret_without_public_manifest_leak() -> None:
    bootstrap = _frontend("lib/devBootstrap.ts")
    viewer = _frontend("components/EncryptedEvidenceViewer.tsx")
    launcher = _backend("scripts/devnet_local_two_frontend_rehearsal.sh")
    backend = _backend("src/weall/api/routes_public_parts/demo_seed.py")
    assert "saveEvidenceKemKeypair(account" in bootstrap
    assert "loadEvidenceKemKeypair(account)" in bootstrap
    assert "loadEvidenceKemKeypair(cleanAccount)" in viewer
    assert '"evidenceKemSecretKeyB64"' in backend
    assert "if _controlled_devnet_bootstrap_secret_enabled():" in backend
    # Browser public manifest is not allowed to include evidence decryption secrets.
    manifest_section = launcher.split("Path(manifest_file).write_text(", 1)[1].split("print(f'wrote", 1)[0]
    assert "kem_secret_b64" not in manifest_section


def test_reviewer_acceptance_requires_encryption_access_and_explains_blocker() -> None:
    juror = _frontend("pages/JurorDashboard.tsx")
    assert "loadEvidenceKemKeypair(account)" in juror
    assert "bind.key_envelope_principals.includes(account)" in juror
    assert "applicant must complete the reviewer-specific encrypted evidence binding" in juror
    assert "Review transaction submitted. Waiting for an on-chain receipt." in juror
    language = _frontend("lib/userLanguage.ts")
    assert 'lower.includes("async_reviewer_key_envelope_required")' in language
    assert 'lower.includes("poh")' not in language


def test_rejected_transactions_do_not_reenter_public_mempool() -> None:
    tx = _backend("src/weall/api/routes_public_parts/tx.py")
    assert "indexed = _tx_index_lookup(request, tx_id)" in tx
    assert '"already_finalized_rejected"' in tx
    assert tx.index('indexed = _tx_index_lookup(request, tx_id)') < tx.index('meta = ex.submit_tx(body, ingress="http")')
    helper = _backend("scripts/devnet_tx.py")
    assert "/nonce" in helper
    assert "int(summary[\"next_nonce\"])" in helper
    assert 'status in {"confirmed", "rejected"}' in helper


def test_devnet_helper_nonce_is_pending_aware(monkeypatch) -> None:
    spec = importlib.util.spec_from_file_location("weall_devnet_tx_regression", ROOT / "scripts/devnet_tx.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    seen: list[str] = []

    def fake_request(method: str, api: str, route: str, *args, **kwargs):
        assert method == "GET"
        seen.append(route)
        return {"ok": True, "chain_nonce": 15, "mempool_pending_max_nonce": 16, "next_nonce": 17}

    monkeypatch.setattr(module, "_http_json", fake_request)
    assert module._next_nonce("http://127.0.0.1:8001", "@devnet-genesis") == 17
    assert seen == ["/v1/accounts/%40devnet-genesis/nonce"]
