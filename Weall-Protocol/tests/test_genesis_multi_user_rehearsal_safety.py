from __future__ import annotations

import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = str(ROOT / "generated" / "tx_index.json")
CHAIN_ID = "weall-batch352-multi-user"
INIT_IDENTITY = ROOT / "scripts" / "init_prod_node_identity.sh"
DEVNET_FULL = ROOT / "scripts" / "devnet_full_onboarding_e2e.sh"


def _new_key() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    priv_seed = private.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub = private.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return priv_seed.hex(), pub.hex()


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
    parent: str | None = None,
) -> dict:
    tx = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "chain_id": CHAIN_ID,
    }
    if parent is not None:
        tx["parent"] = parent
    return sign_tx_envelope_dict(
        tx=tx,
        privkey=account_privkey,
        encoding="hex",
    )


def _produce_until_confirmed(ex: WeAllExecutor, tx_id: str) -> None:
    status = {"ok": True, "status": "pending"}
    for _ in range(4):
        produced = ex.produce_block(max_txs=50)
        assert produced.ok is True, produced.error
        status = ex.get_tx_status(tx_id)
        assert status["ok"] is True
        if status["status"] == "confirmed":
            return
    raise AssertionError(f"tx not confirmed: tx_id={tx_id} status={status}")


def _submit_and_commit(ex: WeAllExecutor, tx: dict) -> str:
    submitted = ex.submit_tx(dict(tx), ingress="http")
    assert submitted["ok"] is True, submitted
    tx_id = str(submitted["tx_id"])
    _produce_until_confirmed(ex, tx_id)
    return tx_id


def test_prod_node_identity_initializer_creates_once_and_emits_exports_batch352(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["WEALL_NODE_PRIVKEY_FILE"] = str(tmp_path / "custom-node.priv")
    env["WEALL_NODE_PUBKEY_FILE"] = str(tmp_path / "custom-node.pub")

    custom_missing = subprocess.run(
        ["bash", str(INIT_IDENTITY)],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert custom_missing.returncode != 0
    assert "custom key paths are set but files do not exist" in custom_missing.stderr

    env.pop("WEALL_NODE_PRIVKEY_FILE", None)
    env.pop("WEALL_NODE_PUBKEY_FILE", None)
    isolated_root = tmp_path / "repo"
    isolated_root.mkdir()
    (isolated_root / "scripts").mkdir()
    (isolated_root / "scripts" / "init_prod_node_identity.sh").write_text(
        INIT_IDENTITY.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (isolated_root / "scripts" / "genesis_generate_node_key.py").write_text(
        (ROOT / "scripts" / "genesis_generate_node_key.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    created = subprocess.run(
        ["bash", str(isolated_root / "scripts" / "init_prod_node_identity.sh"), "--emit-shell-env"],
        cwd=str(isolated_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert created.returncode == 0, created.stderr + created.stdout
    assert "export WEALL_NODE_PRIVKEY_FILE=" in created.stdout
    assert "export WEALL_NODE_PUBKEY_FILE=" in created.stdout
    assert (isolated_root / "secrets" / "weall_node_privkey").is_file()
    assert (isolated_root / "secrets" / "weall_node_pubkey").is_file()

    reused = subprocess.run(
        ["bash", str(isolated_root / "scripts" / "init_prod_node_identity.sh"), "--emit-shell-env"],
        cwd=str(isolated_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert reused.returncode == 0, reused.stderr + reused.stdout
    assert reused.stdout == created.stdout


def test_controlled_devnet_full_onboarding_proves_node2_convergence_batch352() -> None:
    script = DEVNET_FULL.read_text(encoding="utf-8")
    assert 'WEALL_NODE2_BLOCK_LOOP_AUTOSTART:-0' in script
    assert 'bash ./scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}"' in script
    assert 'bash ./scripts/devnet_compare_state_roots.sh' in script
    assert '|| true' not in script.split('echo "==> Comparing state roots after native async Tier-1 onboarding"', 1)[1].split('fi', 1)[0]
    assert 'node2_convergence_tx_id="$(_submit_node2_convergence_tx "${ACCOUNT}")"' in script
    assert 'WEALL_NODE2_CONVERGENCE_TX_TYPE:-FOLLOW_SET' in script
    assert 'unsupported WEALL_NODE2_CONVERGENCE_TX_TYPE' in script


def test_genesis_accepts_multiple_external_observer_users_with_isolated_nonces_batch352(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _set_genesis_env(monkeypatch)
    genesis = WeAllExecutor(
        db_path=str(tmp_path / "genesis.db"),
        node_id="genesis-node",
        chain_id=CHAIN_ID,
        tx_index_path=TX_INDEX,
    )

    users: list[dict[str, str]] = []
    for idx in range(3):
        account_priv, account_pub = _new_key()
        _node_priv, node_pub = _new_key()
        users.append(
            {
                "account": f"@observer_user_{idx}",
                "account_priv": account_priv,
                "account_pub": account_pub,
                "node_pub": node_pub,
            }
        )

    all_tx_ids: list[str] = []
    for idx, user in enumerate(users):
        account = user["account"]
        register = _signed_tx(
            tx_type="ACCOUNT_REGISTER",
            signer=account,
            nonce=1,
            payload={"pubkey": user["account_pub"]},
            account_privkey=user["account_priv"],
        )
        first = genesis.submit_tx(dict(register), ingress="http")
        duplicate = genesis.submit_tx(dict(register), ingress="http")
        assert first["ok"] is True, first
        assert duplicate["ok"] is True, duplicate
        assert duplicate.get("already_known") is True
        assert duplicate["tx_id"] == first["tx_id"]

        conflicting = _signed_tx(
            tx_type="ACCOUNT_REGISTER",
            signer=account,
            nonce=1,
            payload={"pubkey": user["account_pub"]},
            account_privkey=user["account_priv"],
            parent=f"conflicting-parent-{idx}",
        )
        conflict = genesis.submit_tx(dict(conflicting), ingress="http")
        assert conflict["ok"] is False
        assert conflict["error"] == "mempool_signer_nonce_conflict"

        _produce_until_confirmed(genesis, str(first["tx_id"]))
        all_tx_ids.append(str(first["tx_id"]))

        steps = [
            (
                "ACCOUNT_DEVICE_REGISTER",
                {
                    "device_id": f"node:observer_user_{idx}",
                    "device_type": "node",
                    "label": f"Observer user {idx} node",
                    "pubkey": user["node_pub"],
                },
            ),
            (
                "PEER_ADVERTISE",
                {
                    "peer_id": f"node:observer_user_{idx}",
                    "device_id": f"node:observer_user_{idx}",
                    "node_pubkey": user["node_pub"],
                    "endpoint": f"relay://observer-user-{idx}",
                },
            ),
            (
                "PEER_REQUEST_CONNECT",
                {"peer_id": "genesis-node", "endpoint": "https://genesis.example.test"},
            ),
            (
                "POH_ASYNC_REQUEST_OPEN",
                {
                    "account_id": account,
                    "case_id": f"pohasync:observer_user_{idx}:1",
                    "challenge_id": f"observer_user_{idx}",
                    "response_commitment": "sha256:" + str(idx) * 64,
                },
            ),
            (
                "POH_ASYNC_EVIDENCE_DECLARE",
                {
                    "case_id": f"pohasync:observer_user_{idx}:1",
                    "evidence_id": f"async-evidence:observer_user_{idx}:1",
                    "evidence_commitment": "sha256:" + str(idx) * 64,
                    "kind": "observer-onboarding-commitment",
                },
            ),
            (
                "POH_ASYNC_EVIDENCE_BIND",
                {
                    "case_id": f"pohasync:observer_user_{idx}:1",
                    "evidence_id": f"async-evidence:observer_user_{idx}:1",
                    "target_id": f"pohasync:observer_user_{idx}:1",
                },
            ),
        ]
        for nonce, (tx_type, payload) in enumerate(steps, start=2):
            tx_id = _submit_and_commit(
                genesis,
                _signed_tx(
                    tx_type=tx_type,
                    signer=account,
                    nonce=nonce,
                    payload=payload,
                    account_privkey=user["account_priv"],
                ),
            )
            all_tx_ids.append(tx_id)

    state = genesis.read_state()
    for idx, user in enumerate(users):
        account = user["account"]
        acct = state["accounts"][account]
        assert int(acct["nonce"]) == 7
        assert acct["poh_tier"] == 0
        assert acct["devices"]["by_id"][f"node:observer_user_{idx}"]["pubkey"] == user["node_pub"]
        assert state["peers"]["ads"][account]["peer_id"] == f"node:observer_user_{idx}"
        assert state["poh"]["async_cases"][f"pohasync:observer_user_{idx}:1"]["account_id"] == account

    assert len(all_tx_ids) == 21
    assert len(set(all_tx_ids)) == len(all_tx_ids)
    for tx_id in all_tx_ids:
        assert genesis.get_tx_status(tx_id)["status"] == "confirmed"
