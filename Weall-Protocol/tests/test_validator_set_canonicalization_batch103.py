from __future__ import annotations

from weall.ledger.roles_schema import ensure_roles_schema
from weall.runtime.genesis_config import GenesisConfig, GenesisValidator, apply_genesis_config_to_ledger_state
from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(payload: dict, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(
        tx_type="VALIDATOR_SET_UPDATE",
        signer="SYSTEM",
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=f"p:{max(0, int(nonce) - 1)}",
        system=True,
    )


def test_roles_schema_canonicalizes_validator_active_set() -> None:
    state = {"roles": {"validators": {"active_set": ["v2", "v1", "v2"]}}}
    ensure_roles_schema(state)
    assert state["roles"]["validators"]["active_set"] == ["v1", "v2"]


def test_genesis_persists_canonical_validator_active_set() -> None:
    state: dict = {"height": 0, "accounts": {}, "roles": {}}
    cfg = GenesisConfig(
        chain_id="weall",
        validators=[
            GenesisValidator(account="v2", pubkey="pk2", active=True),
            GenesisValidator(account="v1", pubkey="pk1", active=True),
        ],
        active_set=["v2", "v1", "v2"],
    )
    changed, out = apply_genesis_config_to_ledger_state(state, cfg)
    assert changed is True
    assert out["roles"]["validators"]["active_set"] == ["v1", "v2"]


def test_pending_validator_set_is_persisted_canonically() -> None:
    st: dict = {}
    meta = apply_tx(st, _env({"active_set": ["v2", "v1", "v2"], "activate_at_epoch": 3}))
    assert meta["pending"] is True
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["active_set"] == ["v1", "v2"]
