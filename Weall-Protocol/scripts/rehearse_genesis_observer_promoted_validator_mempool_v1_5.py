#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.net.messages import MsgType, TxEnvelopeMsg, WireHeader
from weall.net.net_loop import NetMeshLoop
from weall.runtime.executor import WeAllExecutor
from weall.runtime.node_lifecycle import evaluate_node_lifecycle_status
from weall.runtime.protocol_profile import runtime_protocol_profile_hash
from weall.runtime.state_hash import compute_state_root
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt

Json = dict[str, Any]
CHAIN_ID = "weall-b615-controlled-local-rehearsal"
PROMOTED = "@b615_promoted_validator"
NODE_PUBKEY = "node-pubkey:b615-promoted"
BFT_PUBKEY = "bft-pubkey:b615-promoted"
SCHEMA_VERSION = "1"


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


@contextlib.contextmanager
def _patched_env(values: dict[str, str], *, clear_weall: bool = False) -> Iterator[None]:
    old = os.environ.copy()
    try:
        if clear_weall:
            for key in list(os.environ):
                if key.startswith("WEALL_"):
                    os.environ.pop(key, None)
        os.environ.update({str(k): str(v) for k, v in values.items()})
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def _tx_index_path() -> str:
    return str(ROOT / "generated" / "tx_index.json")


def _base_rehearsal_env() -> dict[str, str]:
    return {
        "WEALL_MODE": "testnet",
        "WEALL_SIGVERIFY": "0",
        "WEALL_STRICT_TX_SIG_DOMAIN": "0",
        "WEALL_ALLOW_LEGACY_SIG_DOMAIN": "1",
        "WEALL_UNSAFE_DEV": "1",
        "WEALL_REQUIRE_VRF": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
        "WEALL_NET_LOOP_AUTOSTART": "0",
        "WEALL_MEMPOOL_SELECTION_POLICY": "canonical",
    }


def _observer_env() -> dict[str, str]:
    env = _base_rehearsal_env()
    env.update(
        {
            "WEALL_NODE_LIFECYCLE_STATE": "observer_onboarding",
            "WEALL_OBSERVER_MODE": "1",
            "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
            "WEALL_SERVICE_ROLES": "",
        }
    )
    return env


def _observer_prod_probe_env() -> dict[str, str]:
    return {
        "WEALL_MODE": "prod",
        "WEALL_NODE_LIFECYCLE_STATE": "observer_onboarding",
        "WEALL_OBSERVER_MODE": "1",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
        "WEALL_NET_LOOP_AUTOSTART": "0",
        "WEALL_SIGVERIFY": "1",
        "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_CHAIN_ID": CHAIN_ID,
    }


def _genesis_env() -> dict[str, str]:
    env = _base_rehearsal_env()
    env.update(
        {
            "WEALL_NODE_LIFECYCLE_STATE": "bootstrap_registration",
            "WEALL_OBSERVER_MODE": "0",
            "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
            "WEALL_SERVICE_ROLES": "node_operator",
        }
    )
    return env


def _production_validator_env() -> dict[str, str]:
    return {
        "WEALL_MODE": "prod",
        "WEALL_NODE_LIFECYCLE_STATE": "production_service",
        "WEALL_SERVICE_ROLES": "node_operator,validator",
        "WEALL_OBSERVER_MODE": "0",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "1",
        "WEALL_BFT_ENABLED": "1",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_SIGVERIFY": "1",
        "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_BOUND_ACCOUNT": PROMOTED,
        "WEALL_VALIDATOR_ACCOUNT": PROMOTED,
        "WEALL_NODE_PUBKEY": NODE_PUBKEY,
        "WEALL_NODE_PUBLIC_KEY": NODE_PUBKEY,
        "WEALL_CHAIN_ID": CHAIN_ID,
    }


def _make_executor(root: Path, node_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(root / f"{node_id}.sqlite"),
        node_id=node_id,
        chain_id=CHAIN_ID,
        tx_index_path=_tx_index_path(),
    )


def _install_promoted_validator_state(executors: list[WeAllExecutor]) -> Json:
    readiness = build_validator_readiness_receipt(
        account_id=PROMOTED,
        node_pubkey=NODE_PUBKEY,
        bft_pubkey=BFT_PUBKEY,
        chain_id=CHAIN_ID,
        schema_version=SCHEMA_VERSION,
        protocol_version="v1.5",
        manifest_hash=_sha({"chain_id": CHAIN_ID, "kind": "controlled-local-rehearsal"}),
        tx_index_hash=executors[0].tx_index_hash(),
        runtime_profile_hash=runtime_protocol_profile_hash(),
        readiness_expires_height=10_000,
    )
    state_patch = {
        "chain_id": CHAIN_ID,
        "height": 0,
        "params": {"chain_id": CHAIN_ID, "economics_enabled": False},
        "accounts": {
            PROMOTED: {
                "poh_tier": 2,
                "reputation": "10",
                "reputation_milli": 10_000,
                "banned": False,
                "locked": False,
                "devices": {
                    "by_id": {
                        "node:b615-promoted": {
                            "device_id": "node:b615-promoted",
                            "device_type": "node",
                            "label": "Batch 615 promoted validator node",
                            "pubkey": NODE_PUBKEY,
                            "active": True,
                        }
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "active_set": [PROMOTED],
                "by_id": {
                    PROMOTED: {
                        "enrolled": True,
                        "active": True,
                        "status": "active",
                        "responsibilities": {
                            "validator": {
                                "opted_in": True,
                                "active": True,
                                "readiness_status": "verified",
                                "reputation_required_milli": 5_000,
                                "reputation_actual_milli": 10_000,
                                "node_pubkey": NODE_PUBKEY,
                                "bft_pubkey": BFT_PUBKEY,
                                "chain_id": CHAIN_ID,
                                "schema_version": SCHEMA_VERSION,
                                "protocol_version": "v1.5",
                                "manifest_hash": readiness["manifest_hash"],
                                "tx_index_hash": readiness["tx_index_hash"],
                                "runtime_profile_hash": readiness["runtime_profile_hash"],
                                "readiness_checks": readiness["readiness_checks"],
                                "readiness_receipt_hash": readiness["readiness_receipt_hash"],
                                "readiness_expires_height": readiness["readiness_expires_height"],
                            },
                            "storage": {
                                "opted_in": False,
                                "active": False,
                                "declared_capacity_bytes": 0,
                                "proven_capacity_bytes": 0,
                                "allocated_capacity_bytes": 0,
                                "proof_status": "not_requested",
                            },
                        },
                    }
                },
            },
            "validators": {
                "active_set": [PROMOTED],
                "by_id": {
                    PROMOTED: {
                        "active": True,
                        "node_pubkey": NODE_PUBKEY,
                        "readiness_receipt_hash": readiness["readiness_receipt_hash"],
                    }
                },
            },
        },
    }
    for ex in executors:
        merged = dict(ex.read_state())
        merged.update({k: v for k, v in state_patch.items() if k not in {"accounts", "roles", "params"}})
        merged.setdefault("accounts", {}).update(state_patch["accounts"])
        merged.setdefault("roles", {}).update(state_patch["roles"])
        merged.setdefault("params", {}).update(state_patch["params"])
        ex.state = merged
        ex._ledger_store.write(ex.state)
    return readiness


def _user_tx(signer: str, nonce: int, label: str) -> Json:
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": int(nonce),
        "payload": {"pubkey": f"pubkey:{label}"},
        "chain_id": CHAIN_ID,
    }


def _tx_msg(tx: Json) -> TxEnvelopeMsg:
    return TxEnvelopeMsg(
        header=WireHeader(type=MsgType.TX_ENVELOPE, chain_id=CHAIN_ID, schema_version=SCHEMA_VERSION, tx_index_hash=""),
        nonce=int(tx.get("nonce") or 0),
        client_tx_id=str(tx.get("client_tx_id") or ""),
        tx=tx,
    )


def _gossip_to(executor: WeAllExecutor, tx: Json, *, peer_id: str = "peer") -> None:
    loop = NetMeshLoop(executor=executor, mempool=executor._mempool, cfg=None)
    loop._on_tx(peer_id, _tx_msg(json.loads(json.dumps(tx, sort_keys=True))))


def _selection_ids(executor: WeAllExecutor) -> list[str]:
    return [str(tx.get("tx_id") or "") for tx in executor._mempool.fetch_for_block(limit=100, policy="canonical")]


def _mempool_snapshot(executor: WeAllExecutor) -> Json:
    return {
        "node_id": executor.node_id,
        "size": executor._mempool.size(),
        "selection_policy": executor._mempool.selection_policy(),
        "tx_ids": _selection_ids(executor),
    }


def _latest_block(executor: WeAllExecutor) -> Json:
    height = int(executor.state.get("height") or 0)
    block = executor.get_block_by_height(height)
    if not isinstance(block, dict):
        raise RuntimeError(f"missing_block_at_height:{height}")
    return block


def run_harness(*, work_dir: str | Path | None = None) -> Json:
    old_env = os.environ.copy()
    try:
        root_ctx = tempfile.TemporaryDirectory(prefix="weall-b615-rehearsal-") if work_dir is None else None
        root = Path(root_ctx.name if root_ctx is not None else work_dir).resolve()  # type: ignore[union-attr]
        root.mkdir(parents=True, exist_ok=True)
        with _patched_env(_genesis_env(), clear_weall=True):
            genesis = _make_executor(root, "genesis")
        with _patched_env(_observer_env(), clear_weall=True):
            observer = _make_executor(root, "observer")
            observer_mode_at_boot = bool(observer.observer_mode())
            observer_signing_permitted = bool(observer._validator_signing_permitted())
        with _patched_env(_observer_prod_probe_env(), clear_weall=True):
            observer_probe = _make_executor(root, "observer-produce-probe")
            observer_produce = observer_probe.produce_block(allow_empty=True)
        with _patched_env(_base_rehearsal_env(), clear_weall=True):
            promoted = _make_executor(root, "promoted-validator")
            readiness = _install_promoted_validator_state([genesis, observer, promoted])

            txs = [
                _user_tx("@b615_carol", 1, "carol"),
                _user_tx("@b615_alice", 1, "alice"),
                _user_tx("@b615_bob", 1, "bob"),
            ]

            # Node A accepts in one order. Node B/C receive the same gossip in
            # intentionally different orders to prove canonical selection is not
            # arrival-order dependent.
            genesis_admissions = [genesis.submit_tx(dict(tx), ingress="local_fixture") for tx in txs]
            for tx in reversed(txs):
                _gossip_to(observer, tx, peer_id="genesis")
            for tx in [txs[1], txs[2], txs[0]]:
                _gossip_to(promoted, tx, peer_id="genesis")

            before_commit = {
                "genesis": _mempool_snapshot(genesis),
                "observer": _mempool_snapshot(observer),
                "promoted_validator": _mempool_snapshot(promoted),
            }
            canonical_converged_before_commit = (
                before_commit["genesis"]["tx_ids"]
                == before_commit["observer"]["tx_ids"]
                == before_commit["promoted_validator"]["tx_ids"]
            )

            duplicate_before = observer._mempool.size()
            _gossip_to(observer, txs[0], peer_id="duplicate-peer")
            duplicate_after = observer._mempool.size()

            wrong_chain = dict(txs[0])
            wrong_chain["chain_id"] = CHAIN_ID + "-wrong"
            invalid_before = promoted._mempool.size()
            _gossip_to(promoted, wrong_chain, peer_id="wrong-chain-peer")
            invalid_after = promoted._mempool.size()

            conflict = dict(txs[0])
            conflict["payload"] = {"pubkey": "pubkey:conflict"}
            conflict_result = genesis.submit_tx(conflict, ingress="local_fixture")

            produced = genesis.produce_block(max_txs=10, allow_empty=False)
            produced_ok = bool(getattr(produced, "ok", False))
            block = _latest_block(genesis)
            observer_apply = observer.apply_block(block)
            promoted_apply = promoted.apply_block(block)

            after_commit = {
                "genesis": _mempool_snapshot(genesis),
                "observer": _mempool_snapshot(observer),
                "promoted_validator": _mempool_snapshot(promoted),
            }

            roots_after_commit = {
                "genesis": compute_state_root(genesis.read_state()),
                "observer": compute_state_root(observer.read_state()),
                "promoted_validator": compute_state_root(promoted.read_state()),
            }
            heights_after_commit = {
                "genesis": int(genesis.read_state().get("height") or 0),
                "observer": int(observer.read_state().get("height") or 0),
                "promoted_validator": int(promoted.read_state().get("height") or 0),
            }

            restarted = {
                "genesis": _make_executor(root, "genesis"),
                "observer": _make_executor(root, "observer"),
                "promoted_validator": _make_executor(root, "promoted-validator"),
            }
            roots_after_restart = {name: compute_state_root(ex.read_state()) for name, ex in restarted.items()}
            mempool_after_restart = {name: _mempool_snapshot(ex) for name, ex in restarted.items()}

        with _patched_env(_production_validator_env(), clear_weall=True):
            lifecycle = evaluate_node_lifecycle_status(
                state=promoted.read_state(),
                node_id="promoted-validator",
                chain_id=CHAIN_ID,
                schema_version=SCHEMA_VERSION,
                tx_index_hash=promoted.tx_index_hash(),
                runtime_profile_hash=str(readiness.get("runtime_profile_hash") or "runtime-profile:b615"),
            ).to_json()

        ok = all(
            [
                observer_mode_at_boot,
                not observer_signing_permitted,
                not bool(getattr(observer_produce, "ok", False)),
                all(bool(item.get("ok")) for item in genesis_admissions),
                canonical_converged_before_commit,
                duplicate_before == duplicate_after,
                invalid_before == invalid_after,
                not bool(conflict_result.get("ok")),
                str(conflict_result.get("error")) == "mempool_signer_nonce_conflict",
                produced_ok,
                bool(getattr(observer_apply, "ok", False)),
                bool(getattr(promoted_apply, "ok", False)),
                len(set(roots_after_commit.values())) == 1,
                len(set(roots_after_restart.values())) == 1,
                all(int(snap.get("size") or 0) == 0 for snap in after_commit.values()),
                all(int(snap.get("size") or 0) == 0 for snap in mempool_after_restart.values()),
                lifecycle.get("effective_state") == "production_service",
                "validator" in set(lifecycle.get("service_roles_effective") or []),
                not lifecycle.get("promotion_failure_reasons"),
            ]
        )

        out = {
            "schema": "weall.v1_5.batch615.genesis_observer_promoted_validator_mempool_rehearsal",
            "batch": "615",
            "ok": bool(ok),
            "claim_boundary": "controlled_local_rehearsal_only_not_public_beta_or_mainnet",
            "chain_id": CHAIN_ID,
            "observer_boot": {
                "observer_mode": observer_mode_at_boot,
                "validator_signing_permitted": observer_signing_permitted,
                "observer_can_produce_block": bool(getattr(observer_produce, "ok", False)),
                "observer_produce_error": getattr(observer_produce, "error", None),
            },
            "promoted_validator": {
                "account_id": PROMOTED,
                "node_pubkey": NODE_PUBKEY,
                "readiness_receipt_hash": readiness.get("readiness_receipt_hash"),
                "lifecycle": lifecycle,
            },
            "mempool": {
                "admission_results": genesis_admissions,
                "before_commit": before_commit,
                "canonical_converged_before_commit": canonical_converged_before_commit,
                "duplicate_replay_ignored": duplicate_before == duplicate_after,
                "invalid_wrong_chain_rejected": invalid_before == invalid_after,
                "nonce_conflict_rejected": not bool(conflict_result.get("ok")) and str(conflict_result.get("error")) == "mempool_signer_nonce_conflict",
                "nonce_conflict_result": conflict_result,
                "after_commit": after_commit,
                "after_restart": mempool_after_restart,
            },
            "block_finalization": {
                "produced_ok": produced_ok,
                "height": int(block.get("height") or 0),
                "block_id": str(block.get("block_id") or block.get("id") or ""),
                "observer_apply_ok": bool(getattr(observer_apply, "ok", False)),
                "promoted_validator_apply_ok": bool(getattr(promoted_apply, "ok", False)),
                "heights_after_commit": heights_after_commit,
                "roots_after_commit": roots_after_commit,
                "roots_after_restart": roots_after_restart,
                "state_converged_after_commit": len(set(roots_after_commit.values())) == 1,
                "state_converged_after_restart": len(set(roots_after_restart.values())) == 1,
            },
            "work_dir": str(root) if work_dir is not None else "temporary",
        }
        return out
    finally:
        os.environ.clear()
        os.environ.update(old_env)
        try:
            if 'root_ctx' in locals() and root_ctx is not None:
                root_ctx.cleanup()  # type: ignore[name-defined]
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Batch 615 controlled local Genesis→observer→promoted-validator mempool convergence rehearsal.")
    parser.add_argument("--json", action="store_true", help="pretty-print JSON")
    parser.add_argument("--work-dir", default="", help="optional persistent work directory for debugging")
    parser.add_argument("--write-report", default="", help="optional path to write the JSON report")
    args = parser.parse_args()

    report = run_harness(work_dir=args.work_dir or None)
    text = json.dumps(report, sort_keys=True, indent=2 if args.json else None) + "\n"
    if args.write_report:
        path = Path(args.write_report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
