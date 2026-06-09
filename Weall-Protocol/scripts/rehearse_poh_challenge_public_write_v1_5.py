#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _post(client: TestClient, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    resp = client.post(path, json=payload)
    if resp.status_code >= 400:
        raise RuntimeError(f"api_post_failed:{path}:{resp.status_code}:{resp.text}")
    return resp.json()


def _produce(ex: WeAllExecutor, *, max_txs: int = 4) -> None:
    res = ex.produce_block(max_txs=max_txs)
    if not bool(getattr(res, "ok", False)):
        raise RuntimeError(f"produce_block_failed:{res}")


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    try:
        os.environ["WEALL_MODE"] = "testnet"
        os.environ["WEALL_SIGVERIFY"] = "0"
        os.environ["WEALL_UNSAFE_DEV"] = "1"
        os.environ["WEALL_PRODUCE_EMPTY_BLOCKS"] = "1"
        with tempfile.TemporaryDirectory(prefix="weall-b549-poh-challenge-api-") as td:
            ex = WeAllExecutor(
                db_path=str(Path(td) / "node.sqlite"),
                node_id="b549-node",
                chain_id="batch549-poh-challenge-api",
                tx_index_path=_tx_index_path(),
            )
            app = create_app(boot_runtime=False)
            app.state.executor = ex
            client = TestClient(app)

            # Register both target and challenger through the public write path.
            _post(client, "/v1/tx/submit", {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "chain_id": "batch549-poh-challenge-api", "payload": {"pubkey": "k:alice"}, "sig": "sig"})
            _post(client, "/v1/tx/submit", {"tx_type": "ACCOUNT_REGISTER", "signer": "@bob", "nonce": 1, "chain_id": "batch549-poh-challenge-api", "payload": {"pubkey": "k:bob"}, "sig": "sig"})
            _produce(ex, max_txs=2)
            st = ex.read_state()
            st.setdefault("accounts", {}).setdefault("@alice", {})["poh_tier"] = 1
            st.setdefault("accounts", {}).setdefault("@bob", {})["poh_tier"] = 1
            st.setdefault("poh", {}).setdefault("async_cases", {})["case-a"] = {
                "case_id": "case-a",
                "account_id": "@alice",
                "status": "approved",
                "reviews": {"@reviewer": {"verdict": "approve"}},
            }
            ex._ledger_store.write(st); ex.state = ex._ledger_store.read()

            skeleton = _post(client, "/v1/poh/challenge/tx/open", {"account_id": "@alice", "case_id": "case-a", "reason": "duplicate-human"})
            tx = dict(skeleton["tx"])
            envelope = {
                "tx_type": tx["tx_type"],
                "signer": "@bob",
                "nonce": 2,
                "chain_id": "batch549-poh-challenge-api",
                "payload": tx["payload"],
                "sig": "sig",
            }
            submit = _post(client, "/v1/tx/submit", envelope)
            _produce(ex, max_txs=1)
            final_state = ex.read_state()
            challenge_id = "pohc:@alice:2"
            challenge = final_state.get("poh", {}).get("challenges", {}).get(challenge_id, {})
            return {
                "ok": bool(skeleton.get("ok") and submit.get("ok") and challenge.get("status") == "open"),
                "batch": "549",
                "skeleton_route": "POST /v1/poh/challenge/tx/open",
                "submit_route": "POST /v1/tx/submit POH_CHALLENGE_OPEN",
                "challenge_id": challenge_id,
                "challenge_status": challenge.get("status"),
                "challenge_case_id": challenge.get("case_id"),
                "public_client_write_gap_closed": True,
                "system_or_receipt_submission_required": False,
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
