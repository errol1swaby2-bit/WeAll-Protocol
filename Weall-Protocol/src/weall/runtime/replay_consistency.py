from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from weall.runtime.block_hash import ensure_block_hash
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from weall.crypto.sig import sign_tx_envelope_dict
from weall.testing.sigtools import deterministic_ed25519_keypair

Json = dict[str, Any]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _block_manifest_entry(block: Json) -> Json:
    blk, bh = ensure_block_hash(dict(block))
    txs = blk.get("txs")
    tx_count = len(txs) if isinstance(txs, list) else 0
    return {
        "height": int(blk.get("height") or 0),
        "block_id": str(blk.get("block_id") or ""),
        "block_hash": str(bh),
        "prev_block_id": str(blk.get("prev_block_id") or ""),
        "view": int(blk.get("view") or 0),
        "tx_count": tx_count,
        "state_root": str(blk.get("state_root") or ""),
        "receipts_root": str(blk.get("receipts_root") or ""),
    }


def build_replay_manifest(executor: WeAllExecutor) -> Json:
    state = dict(executor.read_state())
    height = int(state.get("height") or 0)
    blocks: list[Json] = []
    for h in range(1, height + 1):
        blk = executor.get_block_by_height(h)
        if not isinstance(blk, dict):
            raise RuntimeError(f"missing_block_at_height:{h}")
        blocks.append(_block_manifest_entry(blk))

    latest = executor.get_latest_block() if height > 0 else None
    latest_entry = _block_manifest_entry(latest) if isinstance(latest, dict) else None
    return {
        "chain_id": str(executor.chain_id or ""),
        "height": height,
        "tip": str(state.get("tip") or ""),
        "tip_hash": str(state.get("tip_hash") or ""),
        "computed_state_root": compute_state_root(state),
        "latest_block": latest_entry,
        "blocks": blocks,
    }


def compare_replay_manifests(expected: Json, observed: Json) -> list[str]:
    issues: list[str] = []
    for key in ("chain_id", "height", "tip", "tip_hash", "computed_state_root"):
        if expected.get(key) != observed.get(key):
            issues.append(
                f"manifest_mismatch:{key}:expected={expected.get(key)!r}:observed={observed.get(key)!r}"
            )

    exp_blocks = list(expected.get("blocks") or [])
    obs_blocks = list(observed.get("blocks") or [])
    if len(exp_blocks) != len(obs_blocks):
        issues.append(
            f"manifest_mismatch:block_count:expected={len(exp_blocks)}:observed={len(obs_blocks)}"
        )
        return issues

    for idx, (exp, obs) in enumerate(zip(exp_blocks, obs_blocks, strict=True), start=1):
        if not isinstance(exp, dict) or not isinstance(obs, dict):
            issues.append(f"manifest_mismatch:block_entry_type:height={idx}")
            continue
        if exp != obs:
            issues.append(
                f"manifest_mismatch:block:{idx}:expected={json.dumps(exp, sort_keys=True, separators=(',', ':'))}:observed={json.dumps(obs, sort_keys=True, separators=(',', ':'))}"
            )
    return issues


def _submit_account_register(executor: WeAllExecutor, signer: str, nonce: int) -> None:
    pubkey_hex, sk = deterministic_ed25519_keypair(label=signer)
    privkey_hex = sk.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    ).hex()
    tx = sign_tx_envelope_dict(
        tx={
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "chain_id": str(executor.chain_id),
            "payload": {"pubkey": pubkey_hex},
        },
        privkey=privkey_hex,
        encoding="hex",
    )
    res = executor.submit_tx(tx)
    if not bool(res.get("ok")):
        raise RuntimeError(f"submit_failed:{signer}:{nonce}:{json.dumps(res, sort_keys=True)}")


def build_sample_chain(*, work_dir: str, chain_id_prefix: str) -> Json:
    root = Path(work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    source_db = root / "source.sqlite"
    replay_db = root / "replay.sqlite"
    chain_id = f"{str(chain_id_prefix).strip() or 'replay-audit'}-chain"
    tx_index_path = _tx_index_path()

    source = WeAllExecutor(
        db_path=str(source_db),
        node_id="replay-src",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )

    submit_plan = [
        ("@alice", 1),
        ("@bob", 1),
        ("@carol", 1),
        ("@dave", 1),
        ("@erin", 1),
        ("@frank", 1),
    ]
    for signer, nonce in submit_plan:
        _submit_account_register(source, signer, nonce)

    for size in (2, 1, 3):
        meta = source.produce_block(max_txs=size)
        if not bool(meta.ok):
            raise RuntimeError(f"source_produce_failed:{size}:{meta.error}")

    source_manifest = build_replay_manifest(source)
    source_blocks = [
        source.get_block_by_height(h) for h in range(1, int(source_manifest["height"]) + 1)
    ]

    replay = WeAllExecutor(
        db_path=str(replay_db),
        node_id="replay-dst",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    for blk in source_blocks:
        if not isinstance(blk, dict):
            raise RuntimeError("source_block_missing_during_replay")
        meta = replay.apply_block(dict(blk))
        if not bool(meta.ok):
            raise RuntimeError(f"replay_apply_failed:{meta.error}")

    replay_manifest = build_replay_manifest(replay)
    issues = compare_replay_manifests(source_manifest, replay_manifest)
    return {
        "ok": not issues,
        "chain_id": chain_id,
        "source_db": str(source_db),
        "replay_db": str(replay_db),
        "source_manifest": source_manifest,
        "replay_manifest": replay_manifest,
        "issues": issues,
    }
