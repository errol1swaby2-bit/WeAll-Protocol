from __future__ import annotations

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.protocol_profile import (
    PRODUCTION_CONSENSUS_PROFILE,
    production_consensus_env_audit,
    runtime_startup_fingerprint,
    runtime_tx_payload_limits,
    validate_runtime_consensus_profile,
)
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


_PAYLOAD_ENV_NAMES = (
    "WEALL_MAX_TX_PAYLOAD_BYTES",
    "WEALL_MAX_TX_PAYLOAD_DEPTH",
    "WEALL_MAX_TX_PAYLOAD_LIST_LEN",
    "WEALL_MAX_TX_PAYLOAD_DICT_KEYS",
    "WEALL_MAX_TX_PAYLOAD_STR_LEN",
    "WEALL_MAX_TX_PAYLOAD_NODES",
)


def _clear_payload_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PAYLOAD_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def _env(payload: dict | None = None) -> TxEnvelope:
    return TxEnvelope(
        tx_type="PEER_ADVERTISE",
        signer="@alice",
        nonce=1,
        payload=payload or {"endpoint": "tcp://node:9000"},
        sig="sig",
    )


def _ledger() -> LedgerView:
    return LedgerView(
        accounts={
            "@alice": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
            }
        },
        roles={},
    )


def _canon(spec: dict | None = None) -> TxIndex:
    return TxIndex({"PEER_ADVERTISE": spec or {}})


def test_prod_payload_limits_are_pinned_by_consensus_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    _clear_payload_env(monkeypatch)

    limits = runtime_tx_payload_limits()

    assert limits == {
        "max_payload_bytes": PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_bytes,
        "max_payload_depth": PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_depth,
        "max_payload_list_len": PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_list_len,
        "max_payload_dict_keys": PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_dict_keys,
        "max_payload_str_len": PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_str_len,
        "max_payload_nodes": PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_nodes,
    }


def test_prod_payload_limit_env_override_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MAX_TX_PAYLOAD_BYTES", "1024")

    with pytest.raises(ValueError, match="production tx payload limit profile mismatch"):
        admit_tx(_env(), _ledger(), _canon(), context="mempool")


@pytest.mark.parametrize("name", _PAYLOAD_ENV_NAMES)
def test_prod_payload_limit_invalid_env_still_reports_invalid_integer(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv(name, "bogus")

    with pytest.raises(ValueError, match=rf"invalid_integer_env:{name}"):
        admit_tx(_env(), _ledger(), _canon(), context="mempool")


def test_prod_consensus_env_audit_includes_payload_limit_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MAX_TX_PAYLOAD_NODES", "12345")

    audit = production_consensus_env_audit()

    assert audit["ok"] is False
    assert "WEALL_MAX_TX_PAYLOAD_NODES" in audit["violations"]
    with pytest.raises(ValueError, match="WEALL_MAX_TX_PAYLOAD_NODES"):
        validate_runtime_consensus_profile()


def test_startup_fingerprint_commits_payload_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    _clear_payload_env(monkeypatch)

    fp = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1.25.0",
    )

    assert fp["max_tx_payload_bytes"] == PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_bytes
    assert fp["max_tx_payload_depth"] == PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_depth
    assert fp["max_tx_payload_nodes"] == PRODUCTION_CONSENSUS_PROFILE.max_tx_payload_nodes


def test_nonprod_payload_limit_env_remains_local_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_MAX_TX_PAYLOAD_BYTES", "1024")

    large_payload = {"endpoint": "tcp://node:9000", "blob": "x" * 2000}
    verdict = admit_tx(_env(large_payload), _ledger(), _canon(), context="mempool")

    assert verdict.ok is False
    assert verdict.code == "payload_too_large"
