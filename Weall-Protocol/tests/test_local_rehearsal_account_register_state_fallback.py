from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_local_rehearsal_account_register_uses_state_fallback_without_weakening_live_batch399() -> None:
    src = (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(encoding="utf-8")

    assert "Observer account-registration tx status has not proven upstream confirmation yet." in src
    assert "Falling back only for this setup account to state proof on both nodes." in src
    assert "Live/async verification txs still require confirmed-and-synced tx/case visibility." in src
    assert 'if ! _wait_tx_local_state_synced "${NODE2_API}" "${OBSERVER_REGISTER_TX_ID}" 90; then' in src

    # The fallback must prove the account exists on both nodes; it must not
    # remove the account-state checks that keep the browser bootstrap key safe.
    fallback_idx = src.index("Falling back only for this setup account")
    fallback_block = src[fallback_idx:fallback_idx + 500]
    assert '_wait_account_nonce "${NODE1_API}" "${OBSERVER_ACCOUNT}" 1 30' in fallback_block
    assert '_wait_account_nonce "${NODE2_API}" "${OBSERVER_ACCOUNT}" 1 30' in fallback_block

    # The normal post-blocking wait remains present after the fallback block.
    assert '_wait_account_nonce "${NODE2_API}" "${OBSERVER_ACCOUNT}" 1 75' in src
