from __future__ import annotations

from pathlib import Path

from nacl.signing import SigningKey

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[2]
TX_INDEX = str(ROOT / "generated" / "tx_index.json")
CHAIN_ID = "weall-prod-observer-signed-e2e"


def _new_key() -> tuple[str, str]:
    sk = SigningKey.generate()
    return sk.encode().hex(), sk.verify_key.encode().hex()


def _set_observer_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "observer_onboarding")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)


def _set_genesis_env(monkeypatch) -> None:
    node_priv, node_pub = _new_key()
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    monkeypatch.setenv("WEALL_STRICT_TX_SIG_DOMAIN", "1")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "0")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", node_priv)
    monkeypatch.setenv("WEALL_NODE_PUBKEY", node_pub)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY_FILE", raising=False)
    monkeypatch.delenv("WEALL_NODE_PUBKEY_FILE", raising=False)
    monkeypatch.delenv("WEALL_UNSAFE_DEV", raising=False)
    monkeypatch.delenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", raising=False)


def _signed_tx(
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    account_privkey: str,
) -> dict:
    return sign_tx_envelope_dict(
        tx={
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
            "chain_id": CHAIN_ID,
        },
        privkey=account_privkey,
        encoding="hex",
    )


def _submit_and_commit(ex: WeAllExecutor, tx: dict) -> str:
    submitted = ex.submit_tx(tx, ingress="http")
    assert submitted["ok"] is True, submitted
    tx_id = str(submitted["tx_id"])
    status = {"ok": True, "status": "pending"}
    for _ in range(3):
        produced = ex.produce_block(max_txs=10)
        assert produced.ok is True, produced.error
        status = ex.get_tx_status(tx_id)
        assert status["ok"] is True
        if status["status"] == "confirmed":
            break
    assert status["status"] == "confirmed", status
    return tx_id


def test_external_observer_signed_onboarding_tx_e2e(tmp_path: Path, monkeypatch) -> None:
    """Model Machine B observer submitting signed onboarding txs to Machine A genesis.

    This stays loopback/CI friendly but keeps the trust boundary: the observer
    generates fresh local account/node keys, never receives genesis authority
    secrets, submits through public-ingress admission, and remains unable to
    produce validator/BFT blocks.
    """

    account_priv, account_pub = _new_key()
    _node_priv, node_pub = _new_key()

    _set_observer_env(monkeypatch)
    observer = WeAllExecutor(
        db_path=str(tmp_path / "observer.db"),
        node_id="observer-node",
        chain_id=CHAIN_ID,
        tx_index_path=TX_INDEX,
    )
    assert observer.observer_mode() is True
    assert observer._validator_signing_permitted() is False
    assert observer.produce_block(allow_empty=True).ok is False

    _set_genesis_env(monkeypatch)
    genesis = WeAllExecutor(
        db_path=str(tmp_path / "genesis.db"),
        node_id="genesis-node",
        chain_id=CHAIN_ID,
        tx_index_path=TX_INDEX,
    )
    assert genesis.tx_index_hash()

    account = "@external_observer_e2e"
    case_id = "pohasync:external_observer_e2e:1"
    evidence_id = "async-evidence:external_observer_e2e:1"
    commitment = "sha256:" + "a" * 64

    steps = [
        (
            "ACCOUNT_REGISTER",
            {"pubkey": account_pub},
        ),
        (
            "ACCOUNT_DEVICE_REGISTER",
            {
                "device_id": "node:external_observer_e2e",
                "device_type": "node",
                "label": "External observer node",
                "pubkey": node_pub,
            },
        ),
        (
            "ACCOUNT_SESSION_KEY_ISSUE",
            {"session_key": "session:external_observer_e2e", "ttl_s": 3600},
        ),
        (
            "PEER_ADVERTISE",
            {
                "peer_id": "node:external_observer_e2e",
                "device_id": "node:external_observer_e2e",
                "node_pubkey": node_pub,
                "endpoint": "relay://observer-node",
            },
        ),
        (
            "PEER_REQUEST_CONNECT",
            {"peer_id": "genesis-node", "endpoint": "https://genesis.example.test"},
        ),
        (
            "PEER_RENDEZVOUS_TICKET_CREATE",
            {
                "ticket_id": "ticket:external_observer_e2e:1",
                "target_peer": "genesis-node",
            },
        ),
        (
            "POH_ASYNC_REQUEST_OPEN",
            {
                "account_id": account,
                "case_id": case_id,
                "challenge_id": "external_observer_e2e",
                "response_commitment": commitment,
            },
        ),
        (
            "POH_ASYNC_EVIDENCE_DECLARE",
            {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "evidence_commitment": commitment,
                "kind": "observer-onboarding-commitment",
            },
        ),
        (
            "POH_ASYNC_EVIDENCE_BIND",
            {"case_id": case_id, "evidence_id": evidence_id, "target_id": case_id},
        ),
    ]

    tx_ids: list[str] = []
    for nonce, (tx_type, payload) in enumerate(steps, start=1):
        tx_ids.append(
            _submit_and_commit(
                genesis,
                _signed_tx(
                    tx_type=tx_type,
                    signer=account,
                    nonce=nonce,
                    payload=payload,
                    account_privkey=account_priv,
                ),
            )
        )

    state = genesis.read_state()
    acct = state["accounts"][account]
    assert acct["poh_tier"] == 0
    assert acct["devices"]["by_id"]["node:external_observer_e2e"]["pubkey"] == node_pub
    assert len(acct["session_keys"]) == 1
    assert next(iter(acct["session_keys"])).startswith("skh:v1:")
    assert state["peers"]["ads"][account]["peer_id"] == "node:external_observer_e2e"
    assert state["peers"]["ads"][account]["device_id"] == "node:external_observer_e2e"
    assert state["peers"]["ads"][account]["node_pubkey"] == node_pub
    assert state["peers"]["tickets"]["ticket:external_observer_e2e:1"]["status"] == "active"
    assert state["poh"]["async_cases"][case_id]["account_id"] == account
    assert evidence_id in state["poh"]["async_cases"][case_id]["evidence_commitments"]

    for tx_id in tx_ids:
        assert genesis.get_tx_status(tx_id)["status"] == "confirmed"

    _set_observer_env(monkeypatch)
    assert observer.observer_mode() is True
    assert observer._validator_signing_permitted() is False
    assert observer.produce_block(allow_empty=True).ok is False
