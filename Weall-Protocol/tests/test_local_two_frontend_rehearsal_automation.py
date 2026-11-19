from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_controlled_devnet_can_explicitly_mount_dev_bootstrap_secret_without_demo_seed() -> None:
    src = read("Weall-Protocol/src/weall/api/routes_public_parts/demo_seed.py")
    assert "_controlled_devnet_bootstrap_secret_enabled" in src
    assert "WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE" in src
    assert "WEALL_RUNTIME_PROFILE" in src
    assert "controlled_devnet" in src
    assert '{"prod", "production", "production_like"}' in src


def test_frontend_dev_bootstrap_can_prepare_account_and_session_without_manual_storage_edits() -> (
    None
):
    src = read("web/src/lib/devBootstrap.ts")
    assert "createAccount" in src
    assert "ensureAccountRecord" in src
    assert 'tx_type: "ACCOUNT_REGISTER"' in src
    assert "ensureBackendSession" in src
    assert "waitForAccountRecord" in src
    assert "secretKeyB64" in src


def test_session_login_waits_for_observer_local_nonce_before_chaining_session_tx() -> None:
    src = read("web/src/auth/session.ts")
    start = src.index("async function finishCanonicalDeviceLogin(")
    end = src.index("export async function ensureBackendSession(", start)
    login = src[start:end]
    # The journaled helper now serves both transactions. Check the actual
    # dispatch, receipt, synchronization, and authorization edges, not the
    # obsolete spelling of two inline submission calls.
    helper_end = login.index('await ensureTracked("deviceTx", "ACCOUNT_DEVICE_REGISTER")')
    helper = login[:helper_end]
    assert "submitSignedTxWithNonce({" in helper
    assert "await trackCanonicalLoginTx(attempt, step, signed)" in helper
    assert "txId: tracked.txId" in helper
    assert "minNonce: tracked.nonce" in helper
    positions = [
        helper.index("await waitForConfirmedSessionTransaction("),
        helper.index("if (!confirmed) throw new PendingCanonicalLoginError"),
        helper.index("await waitForLocalAccountNonceAtLeast("),
        helper.index("if (!sessionSynced) throw new PendingCanonicalLoginError"),
        helper.index("return tracked;"),
    ]
    assert positions == sorted(positions)
    positions = [
        helper_end,
        login.index('await ensureTracked("sessionTx", "ACCOUNT_SESSION_KEY_ISSUE")'),
        login.index("await waitForSessionAuthState("),
        login.index("if (!sessionAuthorized) throw new PendingCanonicalLoginError"),
        login.index("setSession({"),
        login.index("clearCanonicalLogin(attempt.scope)"),
    ]
    assert positions == sorted(positions)
    journal = read("web/src/auth/canonicalLoginJournal.ts")
    assert '"ACCOUNT_DEVICE_REGISTER" : "ACCOUNT_SESSION_KEY_ISSUE"' in journal


def test_one_command_rehearsal_starts_two_backends_two_frontends_and_reconcile_worker() -> None:
    src = read("Weall-Protocol/scripts/devnet_local_two_frontend_rehearsal.sh")
    assert "devnet_boot_genesis_node.sh" in src
    assert "devnet_boot_joining_node.sh" in src
    assert "devnet_observer_tx_queue_reconcile_loop.sh" in src
    assert (
        'VITE_WEALL_DEV_BOOTSTRAP_MANIFEST="/weall-local-rehearsal/dev-bootstrap-observer.json"'
        in src
    )
    assert (
        'VITE_WEALL_DEV_BOOTSTRAP_MANIFEST="/weall-local-rehearsal/dev-bootstrap-genesis.json"'
        in src
    )
    assert 'VITE_WEALL_DEV_PROXY_TARGET="${NODE2_API}"' in src
    assert 'VITE_WEALL_DEV_PROXY_TARGET="${NODE1_API}"' in src
    assert 'RUNTIME_DIR="${WEALL_RUNTIME_DIR:-${DEVNET_DIR}/runtime}"' in src
    assert 'WEALL_TX_QUEUE_PATH="${TX_QUEUE_PATH}"' in src
    assert "${REPO_ROOT}/data" not in src
    assert "WEALL_ALLOW_DIRECT_SESSION_MUTATION" not in src
    assert "WEALL_ENABLE_DEMO_SEED_ROUTE=1" not in src


def test_reconcile_loop_uses_operator_tokens_and_never_mutates_consensus_authority() -> None:
    src = read("Weall-Protocol/scripts/devnet_observer_tx_queue_reconcile_loop.sh")
    assert "/v1/observer/edge/tx-queue/drain" in src
    assert "/v1/observer/edge/reconcile/" in src
    assert "x-weall-observer-operator-token" in src
    assert "x-weall-state-sync-operator-token" in src
    assert "${REPO_ROOT}/data" not in src
    assert "${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}/runtime" in src
    assert "VALIDATOR_SIGNING" not in src
    assert "BFT_ENABLED" not in src
