#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

os.environ.setdefault("WEALL_API_BOOT_RUNTIME", "0")
from weall.api.app import create_app
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.apply.storage import apply_storage
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope


class _SnapshotExecutor:
    """Read-only adapter for API reads over an explicitly uncommitted simulation."""

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict[str, Any] | None = None,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        chain_id="batch541-api",
        payload=payload or {},
        sig="sig",
        system=system,
        parent=parent,
    )


def _post(client: TestClient, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    resp = client.post(path, json=payload)
    if resp.status_code >= 400:
        raise RuntimeError(f"api_post_failed:{path}:{resp.status_code}:{resp.text}")
    return resp.json()


def _get(client: TestClient, path: str) -> dict[str, Any]:
    resp = client.get(path)
    if resp.status_code >= 400:
        raise RuntimeError(f"api_get_failed:{path}:{resp.status_code}:{resp.text}")
    return resp.json()


def _produce(ex: WeAllExecutor, *, max_txs: int) -> None:
    meta = ex.produce_block(max_txs=max_txs)
    if not meta.ok:
        raise RuntimeError(f"block_failed:{meta.error}")


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    try:
        os.environ["WEALL_MODE"] = "testnet"
        os.environ["WEALL_SIGVERIFY"] = "0"
        os.environ["WEALL_UNSAFE_DEV"] = "1"
        os.environ["WEALL_PRODUCE_EMPTY_BLOCKS"] = "1"
        with tempfile.TemporaryDirectory(prefix="weall-b541-api-lifecycle-") as td:
            ex = WeAllExecutor(
                db_path=str(Path(td) / "api.sqlite"),
                node_id="api-node",
                chain_id="batch541-api",
                tx_index_path=_tx_index_path(),
            )

            # Open the bounded bootstrap grant before the first committed block.
            # This is genesis fixture configuration, not a same-height rewrite of
            # committed application state.
            genesis = ex.read_state()
            params = genesis.setdefault("params", {})
            params["poh_bootstrap_open"] = True
            params["poh_bootstrap_max_height"] = 100
            ex._ledger_store.write(genesis)
            ex.state = ex._ledger_store.read()

            app = create_app(boot_runtime=False)
            app.state.executor = ex
            client = TestClient(app)
            api_writes: list[str] = []
            api_reads: list[str] = []

            for account in ("@alice", "@bob"):
                _post(
                    client,
                    "/v1/tx/submit",
                    {
                        "tx_type": "ACCOUNT_REGISTER",
                        "signer": account,
                        "nonce": 1,
                        "chain_id": "batch541-api",
                        "payload": {"pubkey": f"k:{account.lstrip('@')}"},
                        "sig": "sig",
                    },
                )
                api_writes.append(f"POST /v1/tx/submit ACCOUNT_REGISTER {account}")
            _produce(ex, max_txs=2)

            for account in ("@alice", "@bob"):
                _post(
                    client,
                    "/v1/tx/submit",
                    {
                        "tx_type": "POH_BOOTSTRAP_TIER2_GRANT",
                        "signer": account,
                        "nonce": 2,
                        "chain_id": "batch541-api",
                        "payload": {"account_id": account},
                        "sig": "sig",
                    },
                )
                api_writes.append(f"POST /v1/tx/submit POH_BOOTSTRAP_TIER2_GRANT {account}")
            _produce(ex, max_txs=2)

            _post(
                client,
                "/v1/tx/submit",
                {
                    "tx_type": "CONTENT_POST_CREATE",
                    "signer": "@alice",
                    "nonce": 3,
                    "chain_id": "batch541-api",
                    "payload": {
                        "post_id": "p-api",
                        "body": "API lifecycle post",
                        "tags": ["weall"],
                    },
                    "sig": "sig",
                },
            )
            api_writes.append("POST /v1/tx/submit CONTENT_POST_CREATE")
            _produce(ex, max_txs=1)

            feed = _get(client, "/v1/feed?rank=production")
            api_reads.append("GET /v1/feed?rank=production")
            session = _get(client, "/v1/session/me")
            api_reads.append("GET /v1/session/me")

            # Domains without public write routes are intentionally exercised on
            # an independent copy of the committed state. Never persist these
            # direct apply results into ledger_state: doing so would replace a
            # state root already committed by the current tip block.
            committed_before = ex.read_state()
            committed_root_before = compute_state_root(committed_before)
            simulated = copy.deepcopy(committed_before)
            simulated["accounts"]["@alice"]["reputation"] = 10
            simulated["accounts"]["@bob"]["reputation"] = 5

            challenge = apply_poh(
                simulated,
                _env(
                    "POH_CHALLENGE_OPEN",
                    "@bob",
                    3,
                    {"account_id": "@alice", "reason": "demo"},
                ),
            )
            challenge_id = str(challenge.get("challenge_id") or "")
            apply_poh(
                simulated,
                _env(
                    "POH_CHALLENGE_RESOLVE",
                    "SYSTEM",
                    1,
                    {"challenge_id": challenge_id, "resolution": "upheld"},
                    system=True,
                    parent="ch-api",
                ),
            )
            apply_dispute(
                simulated,
                _env(
                    "DISPUTE_OPEN",
                    "@bob",
                    4,
                    {
                        "dispute_id": "d-api",
                        "target_type": "account",
                        "target_id": "@alice",
                        "reason": "demo",
                    },
                ),
            )
            apply_dispute(
                simulated,
                _env(
                    "DISPUTE_FINAL_RECEIPT",
                    "SYSTEM",
                    3,
                    {
                        "dispute_id": "d-api",
                        "resolution": {
                            "actions": [
                                {
                                    "tx_type": "ACCOUNT_RESTRICTION_SET",
                                    "payload": {
                                        "account_id": "@alice",
                                        "restriction": "review",
                                    },
                                }
                            ]
                        },
                    },
                    system=True,
                    parent="d-api",
                ),
            )
            apply_dispute(
                simulated,
                _env(
                    "DISPUTE_FINAL_RECEIPT",
                    "SYSTEM",
                    4,
                    {
                        "dispute_id": "d-api",
                        "appeal_resolution": {
                            "decision": "modify",
                            "actions": [
                                {
                                    "tx_type": "ACCOUNT_REINSTATE",
                                    "payload": {"account_id": "@alice"},
                                }
                            ],
                        },
                    },
                    system=True,
                    parent="d-api",
                ),
            )
            simulated.setdefault("storage", {}).setdefault("operators", {})["op-a"] = {
                "enabled": True,
                "capacity_bytes": 1000,
                "used_bytes": 0,
                "allocated_bytes": 0,
            }
            simulated["storage"]["operators"]["op-b"] = {
                "enabled": True,
                "capacity_bytes": 1000,
                "used_bytes": 0,
                "allocated_bytes": 0,
            }
            apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_REQUEST",
                    "@alice",
                    5,
                    {
                        "pin_id": "pin-api",
                        "cid": "QmYwAPJzv5CZsnAzt8auVTLuRtKfXVDRzi4PhN6dZm8D8h",
                        "size_bytes": 10,
                    },
                ),
            )
            apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_CONFIRM",
                    "SYSTEM",
                    5,
                    {"pin_id": "pin-api", "operator_id": "op-a", "ok": False},
                    system=True,
                    parent="pin-api",
                ),
            )
            apply_storage(
                simulated,
                _env(
                    "IPFS_PIN_CONFIRM",
                    "SYSTEM",
                    6,
                    {
                        "pin_id": "pin-api",
                        "operator_id": "op-b",
                        "ok": True,
                        "retrieval_ok": True,
                    },
                    system=True,
                    parent="pin-api",
                ),
            )
            apply_protocol(
                simulated,
                _env(
                    "PROTOCOL_UPGRADE_DECLARE",
                    "SYSTEM",
                    7,
                    {
                        "upgrade_id": "u-api",
                        "version": "v1.5.1",
                        "artifact_hash": "h",
                    },
                    system=True,
                    parent="gov",
                ),
            )
            apply_protocol(
                simulated,
                _env(
                    "PROTOCOL_UPGRADE_ACTIVATE",
                    "SYSTEM",
                    8,
                    {"upgrade_id": "u-api"},
                    system=True,
                    parent="gov",
                ),
            )

            direct_app = create_app(boot_runtime=False)
            direct_app.state.executor = _SnapshotExecutor(simulated)
            direct_client = TestClient(direct_app)
            dispute = _get(direct_client, "/v1/disputes/d-api")
            api_reads.append("GET /v1/disputes/{dispute_id} [uncommitted direct-domain simulation]")

            committed_after = ex.read_state()
            committed_root_after = compute_state_root(committed_after)
            committed_unchanged = committed_root_after == committed_root_before

            challenge_status = (
                simulated.get("poh", {}).get("challenges", {}).get(challenge_id, {}).get("status")
            )
            dispute_remedy_applied = not bool(simulated["accounts"]["@alice"].get("restricted"))
            storage_retrieval_confirmed = (
                simulated.get("storage", {})
                .get("pins", {})
                .get("pin-api", {})
                .get("durability_status")
                == "retrieval_confirmed"
            )
            protocol_upgrade_record_only = (
                simulated.get("protocol", {})
                .get("upgrades", {})
                .get("u-api", {})
                .get("record_only_boundary", {})
                .get("artifact_apply_enabled")
                is False
            )

            return {
                "ok": feed.get("ok") is True
                and dispute.get("ok") is True
                and dispute_remedy_applied
                and committed_unchanged,
                "batch": "541",
                "api_write_routes_exercised": api_writes,
                "api_read_routes_exercised": api_reads,
                "direct_apply_write_domains_remaining": [
                    "poh_challenge",
                    "dispute_final_receipt",
                    "storage_receipt",
                    "protocol_upgrade_record",
                ],
                "direct_apply_persisted": False,
                "direct_apply_simulation_source": "copy_of_committed_executor_state",
                "committed_state_unchanged_by_direct_apply": committed_unchanged,
                "poh_challenge_status": challenge_status,
                "feed_rank_mode": feed.get("ranking", {}).get("mode"),
                "feed_items": len(feed.get("items") or []),
                "session_route_ok": session.get("ok") is True,
                "dispute_remedy_applied": dispute_remedy_applied,
                "storage_retrieval_confirmed": storage_retrieval_confirmed,
                "protocol_upgrade_record_only": protocol_upgrade_record_only,
                "final_state_root": committed_root_after,
                "direct_apply_state_root": compute_state_root(simulated),
            }
    finally:
        os.environ.clear()
        os.environ.update(old)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
