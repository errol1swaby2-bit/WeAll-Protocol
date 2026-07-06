#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any] | None = None, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch541-api", payload=payload or {}, sig="sig", system=system, parent=parent)


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


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    try:
        os.environ["WEALL_MODE"] = "testnet"
        os.environ["WEALL_SIGVERIFY"] = "0"
        os.environ["WEALL_UNSAFE_DEV"] = "1"
        os.environ["WEALL_PRODUCE_EMPTY_BLOCKS"] = "1"
        with tempfile.TemporaryDirectory(prefix="weall-b541-api-lifecycle-") as td:
            ex = WeAllExecutor(db_path=str(Path(td) / "api.sqlite"), node_id="api-node", chain_id="batch541-api", tx_index_path=_tx_index_path())
            app = create_app(boot_runtime=False)
            app.state.executor = ex
            client = TestClient(app)
            api_writes: list[str] = []
            api_reads: list[str] = []

            _post(client, "/v1/tx/submit", {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "chain_id": "batch541-api", "payload": {"pubkey": "k:alice"}, "sig": "sig"})
            api_writes.append("POST /v1/tx/submit ACCOUNT_REGISTER")
            if not ex.produce_block(max_txs=1).ok:
                raise RuntimeError("account_register_block_failed")
            st = ex.read_state()
            st["accounts"]["@alice"]["poh_tier"] = 2
            st["accounts"]["@alice"]["reputation"] = 10
            st.setdefault("accounts", {})["@bob"] = {"nonce": 0, "poh_tier": 2, "reputation": 5, "locked": False, "banned": False}
            ex._ledger_store.write(st); ex.state = ex._ledger_store.read()

            _post(client, "/v1/tx/submit", {"tx_type": "CONTENT_POST_CREATE", "signer": "@alice", "nonce": 2, "chain_id": "batch541-api", "payload": {"post_id": "p-api", "body": "API lifecycle post", "tags": ["weall"]}, "sig": "sig"})
            api_writes.append("POST /v1/tx/submit CONTENT_POST_CREATE")
            if not ex.produce_block(max_txs=1).ok:
                raise RuntimeError("content_block_failed")

            # Exercise a representative PoH/dispute/storage/protocol sequence with runtime apply,
            # then read the results through public routes. Missing public write routes remain visible
            # in the proof rather than silently pretending every write is API-backed.
            st = ex.read_state()
            apply_poh(st, _env("POH_CHALLENGE_OPEN", "@bob", 1, {"account_id": "@alice", "reason": "demo"}))
            apply_poh(st, _env("POH_CHALLENGE_RESOLVE", "SYSTEM", 1, {"challenge_id": "pohc:@alice:1", "resolution": "upheld"}, system=True, parent="ch-api"))
            apply_dispute(st, _env("DISPUTE_OPEN", "@bob", 2, {"dispute_id": "d-api", "target_type": "account", "target_id": "@alice", "reason": "demo"}))
            apply_dispute(st, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 3, {"dispute_id": "d-api", "resolution": {"actions": [{"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "@alice", "restriction": "review"}}]}}, system=True, parent="d-api"))
            apply_dispute(st, _env("DISPUTE_FINAL_RECEIPT", "SYSTEM", 4, {"dispute_id": "d-api", "appeal_resolution": {"decision": "modify", "actions": [{"tx_type": "ACCOUNT_REINSTATE", "payload": {"account_id": "@alice"}}]}}, system=True, parent="d-api"))
            st.setdefault("storage", {}).setdefault("operators", {})["op-a"] = {"enabled": True, "capacity_bytes": 1000, "used_bytes": 0, "allocated_bytes": 0}
            st["storage"]["operators"]["op-b"] = {"enabled": True, "capacity_bytes": 1000, "used_bytes": 0, "allocated_bytes": 0}
            apply_storage(st, _env("IPFS_PIN_REQUEST", "@alice", 3, {"pin_id": "pin-api", "cid": "QmYwAPJzv5CZsnAzt8auVTLuRtKfXVDRzi4PhN6dZm8D8h", "size_bytes": 10}))
            apply_storage(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 5, {"pin_id": "pin-api", "operator_id": "op-a", "ok": False}, system=True, parent="pin-api"))
            apply_storage(st, _env("IPFS_PIN_CONFIRM", "SYSTEM", 6, {"pin_id": "pin-api", "operator_id": "op-b", "ok": True, "retrieval_ok": True}, system=True, parent="pin-api"))
            apply_protocol(st, _env("PROTOCOL_UPGRADE_DECLARE", "SYSTEM", 7, {"upgrade_id": "u-api", "version": "v1.5.1", "artifact_hash": "h"}, system=True, parent="gov"))
            apply_protocol(st, _env("PROTOCOL_UPGRADE_ACTIVATE", "SYSTEM", 8, {"upgrade_id": "u-api"}, system=True, parent="gov"))
            ex._ledger_store.write(st); ex.state = ex._ledger_store.read()

            feed = _get(client, "/v1/feed?rank=production")
            api_reads.append("GET /v1/feed?rank=production")
            session = _get(client, "/v1/session/me")
            api_reads.append("GET /v1/session/me")
            dispute = _get(client, "/v1/disputes/d-api")
            api_reads.append("GET /v1/disputes/{dispute_id}")
            return {
                "ok": bool(feed.get("ok")) and bool(dispute.get("ok", True)) and not bool(ex.read_state()["accounts"]["@alice"].get("restricted")),
                "batch": "541",
                "api_write_routes_exercised": api_writes,
                "api_read_routes_exercised": api_reads,
                "direct_apply_write_domains_remaining": ["poh_challenge", "dispute_final_receipt", "storage_receipt", "protocol_upgrade_record"],
                "poh_challenge_status": ex.read_state().get("poh", {}).get("challenges", {}).get("pohc:@alice:1", {}).get("status") or st.get("poh", {}).get("challenges", {}).get("pohc:@alice:1", {}).get("status"),
                "feed_rank_mode": feed.get("ranking", {}).get("mode"),
                "feed_items": len(feed.get("items") or []),
                "session_route_ok": bool(session.get("ok")),
                "dispute_remedy_applied": not bool(ex.read_state()["accounts"]["@alice"].get("restricted")),
                "storage_retrieval_confirmed": ex.read_state().get("storage", {}).get("pins", {}).get("pin-api", {}).get("durability_status") == "retrieval_confirmed",
                "protocol_upgrade_record_only": ex.read_state().get("protocol", {}).get("upgrades", {}).get("u-api", {}).get("record_only_boundary", {}).get("artifact_apply_enabled") is False,
                "final_state_root": compute_state_root(ex.read_state()),
            }
    finally:
        os.environ.clear(); os.environ.update(old)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
