from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_controlled_devnet_can_explicitly_mount_dev_bootstrap_secret_without_demo_seed() -> None:
    src = read("Weall-Protocol/src/weall/api/routes_public_parts/demo_seed.py")
    assert "_controlled_devnet_bootstrap_secret_enabled" in src
    assert 'WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE' in src
    assert 'WEALL_RUNTIME_PROFILE' in src
    assert 'controlled_devnet' in src
    assert '{"prod", "production", "production_like"}' in src


def test_frontend_dev_bootstrap_can_prepare_account_and_session_without_manual_storage_edits() -> None:
    src = read("web/src/lib/devBootstrap.ts")
    assert "createAccount" in src
    assert "ensureAccountRecord" in src
    assert 'tx_type: "ACCOUNT_REGISTER"' in src
    assert "ensureBackendSession" in src
    assert "waitForAccountRecord" in src
    assert "secretKeyB64" in src


def test_session_login_waits_for_observer_local_nonce_before_chaining_session_tx() -> None:
    src = read("web/src/auth/session.ts")
    assert "waitForLocalAccountNonceAtLeast" in src
    assert "observer_local_state_not_reconciled" in src
    assert 'tx_type: "ACCOUNT_DEVICE_REGISTER"' in src
    assert 'tx_type: "ACCOUNT_SESSION_KEY_ISSUE"' in src
    assert "submitSignedTxWithNonce" in src
    assert src.index('tx_type: "ACCOUNT_DEVICE_REGISTER"') < src.index('tx_type: "ACCOUNT_SESSION_KEY_ISSUE"')


def test_one_command_rehearsal_starts_two_backends_two_frontends_and_reconcile_worker() -> None:
    src = read("Weall-Protocol/scripts/devnet_local_two_frontend_rehearsal.sh")
    assert "devnet_boot_genesis_node.sh" in src
    assert "devnet_boot_joining_node.sh" in src
    assert "devnet_observer_outbox_reconcile_loop.sh" in src
    assert "VITE_WEALL_DEV_BOOTSTRAP_MANIFEST=\"/dev-bootstrap-observer.json\"" in src
    assert "VITE_WEALL_DEV_BOOTSTRAP_MANIFEST=\"/dev-bootstrap-genesis.json\"" in src
    assert "VITE_WEALL_DEV_PROXY_TARGET=\"${NODE2_API}\"" in src
    assert "VITE_WEALL_DEV_PROXY_TARGET=\"${NODE1_API}\"" in src
    assert "WEALL_ALLOW_DIRECT_SESSION_MUTATION" not in src
    assert "WEALL_ENABLE_DEMO_SEED_ROUTE=1" not in src


def test_reconcile_loop_uses_operator_tokens_and_never_mutates_consensus_authority() -> None:
    src = read("Weall-Protocol/scripts/devnet_observer_outbox_reconcile_loop.sh")
    assert "/v1/observer/edge/outbox/drain" in src
    assert "/v1/observer/edge/reconcile/" in src
    assert "x-weall-observer-operator-token" in src
    assert "x-weall-state-sync-operator-token" in src
    assert "VALIDATOR_SIGNING" not in src
    assert "BFT_ENABLED" not in src
