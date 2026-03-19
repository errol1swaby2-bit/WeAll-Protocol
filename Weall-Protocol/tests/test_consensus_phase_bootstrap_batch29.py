from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.bft_hotstuff import (
    BFT_MIN_VALIDATORS,
    CONSENSUS_PHASE_BFT_ACTIVE,
    CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP,
    CONSENSUS_PHASE_SOLO_BOOTSTRAP,
)
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, payload: dict, *, nonce: int = 1, system: bool = True, parent: str = "parent") -> TxEnvelope:
    return TxEnvelope(
        tx_id=f"tx:{tx_type}:{nonce}",
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=nonce,
        payload=payload,
        sig="",
        system=system,
        parent=parent,
    )


def test_immediate_validator_set_update_tracks_bootstrap_phase() -> None:
    st = {"roles": {"validators": {"active_set": []}}, "consensus": {"epochs": {"current": 0}}}
    meta1 = apply_tx(st, _env("VALIDATOR_SET_UPDATE", {"active_set": ["@solo"]}, nonce=1))
    assert meta1["consensus_phase"] == CONSENSUS_PHASE_SOLO_BOOTSTRAP
    assert st["consensus"]["phase"]["current"] == CONSENSUS_PHASE_SOLO_BOOTSTRAP

    meta2 = apply_tx(st, _env("VALIDATOR_SET_UPDATE", {"active_set": ["@v1", "@v2"]}, nonce=2))
    assert meta2["consensus_phase"] == CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP
    assert st["consensus"]["phase"]["current"] == CONSENSUS_PHASE_MULTI_VALIDATOR_BOOTSTRAP


def test_validator_set_update_can_schedule_bft_activation_at_epoch_boundary() -> None:
    st = {"roles": {"validators": {"active_set": ["@solo"]}}, "consensus": {"epochs": {"current": 1}, "phase": {"current": CONSENSUS_PHASE_SOLO_BOOTSTRAP}}}
    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {
                "active_set": ["@v1", "@v2", "@v3", "@v4"],
                "activate_at_epoch": 3,
                "activate_bft_at_epoch": 3,
            },
            nonce=1,
        ),
    )
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["phase"] == CONSENSUS_PHASE_BFT_ACTIVE

    close1 = apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=2))
    assert close1["applied"] == "EPOCH_CLOSE"

    open2 = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=3))
    assert open2["applied"] == "EPOCH_OPEN"
    assert "validator_set_activated" not in open2

    close2 = apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 2}, nonce=4))
    assert close2["applied"] == "EPOCH_CLOSE"

    meta = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 3}, nonce=5))
    assert meta["validator_set_activated"]["consensus_phase"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert st["consensus"]["phase"]["current"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert st["roles"]["validators"]["active_set"] == ["@v1", "@v2", "@v3", "@v4"]


def test_validator_set_update_rejects_bft_activation_below_minimum_validator_count() -> None:
    st = {"roles": {"validators": {"active_set": ["@solo"]}}, "consensus": {"epochs": {"current": 1}}}
    try:
        apply_tx(
            st,
            _env(
                "VALIDATOR_SET_UPDATE",
                {
                    "active_set": ["@v1", "@v2", "@v3"],
                    "activate_at_epoch": 2,
                    "activate_bft_at_epoch": 2,
                },
                nonce=1,
            ),
        )
    except Exception as exc:
        assert "bft_activation_requires_minimum_validator_count" in str(exc)
    else:
        raise AssertionError(f"expected rejection below minimum validator count {BFT_MIN_VALIDATORS}")


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "@validator-1"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "phase-test",
            "height": 9,
            "tip": "9:block",
            "tip_hash": "hash9",
            "tip_ts_ms": 1700000000009,
            "finalized": {"height": 8, "block_id": "8:block"},
            "roles": {"validators": {"active_set": ["@validator-1", "@validator-2", "@validator-3", "@validator-4"]}},
            "consensus": {"phase": {"current": CONSENSUS_PHASE_BFT_ACTIVE}},
            "bft": {"view": 2},
            "meta": {"schema_version": "1", "tx_index_hash": "phase-hash"},
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "phase-hash"


class _FakeNetNode:
    def peers_debug(self) -> dict[str, object]:
        return {"counts": {"peers_total": 0}}


def test_status_consensus_exposes_security_phase_summary(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator-1")
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    app.state.net_node = _FakeNetNode()
    client = TestClient(app)

    body = client.get("/v1/status/consensus").json()
    assert body["consensus_phase"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert body["security_summary"]["public_bft_active"] is True
    assert body["security_summary"]["fault_tolerance"] == 1
