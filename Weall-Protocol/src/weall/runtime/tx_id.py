# src/weall/runtime/tx_id.py
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

# NOTE: TxEnvelope lives in tx_admission_types.
# Importing it directly avoids accidental circular imports and keeps this module
# usable from both admission and execution codepaths.
from weall.runtime.tx_admission_types import TxEnvelope

Json = Dict[str, Any]


def _json_canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_tx_id(
    *,
    chain_id: str,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    system: bool = False,
    parent: Optional[str] = None,
) -> str:
    """
    Canonical tx_id function (single source of truth).

    Contract:
      - Includes chain_id (so identical tx across chains cannot collide)
      - Includes parent if present (affects semantics for receipt-only tx types)
      - Excludes sig (signature encoding MUST NOT affect tx_id)
      - Excludes ts_ms / mempool metadata (non-deterministic)
    """
    obj: Json = {
        "chain_id": str(chain_id),
        "tx_type": str(tx_type),
        "signer": str(signer),
        "nonce": int(nonce),
        "payload": payload if isinstance(payload, dict) else {},
        "system": bool(system),
    }
    if parent is not None:
        obj["parent"] = str(parent)

    return _sha256_hex(_json_canonical(obj))


def compute_tx_id_from_envelope(chain_id: str, env: TxEnvelope) -> str:
    return compute_tx_id(
        chain_id=str(chain_id),
        tx_type=env.tx_type,
        signer=env.signer,
        nonce=int(env.nonce),
        payload=env.payload,
        system=bool(env.system),
        parent=env.parent,
    )


def compute_tx_id_from_dict(chain_id: str, tx: Dict[str, Any]) -> str:
    """
    Backwards compatible helper for codepaths that still hold a raw dict tx envelope.
    Unknown extra keys are ignored.
    """
    tx_type = tx.get("tx_type", "")
    signer = tx.get("signer", "")
    nonce = tx.get("nonce", 0)
    payload = tx.get("payload", {})
    parent = tx.get("parent", None)
    system = tx.get("system", False)

    try:
        nonce_i = int(nonce)
    except Exception:
        nonce_i = 0

    return compute_tx_id(
        chain_id=str(chain_id),
        tx_type=str(tx_type),
        signer=str(signer),
        nonce=nonce_i,
        payload=payload if isinstance(payload, dict) else {},
        system=bool(system),
        parent=str(parent) if parent is not None else None,
    )
