from __future__ import annotations

import hashlib
from typing import Any

from weall.runtime.json_tools import canonical_json_bytes
from weall.runtime.tx_admission_types import TxEnvelope

Json = dict[str, Any]
TX_ID_PREFIX = "tx:"


def _json_canonical(obj: Any) -> bytes:
    return canonical_json_bytes(obj)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_tx_identity(
    *,
    chain_id: str,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    system: bool = False,
    parent: str | None = None,
) -> Json:
    """Return the single consensus transaction-identity object.

    Signature bytes/profile, transport/network metadata, timestamps, and local
    mempool fields are deliberately excluded.  They may prove or transport a
    transaction, but they do not change the transaction's protocol semantics.
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
    return obj


def compute_tx_id(
    *,
    chain_id: str,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: Json,
    system: bool = False,
    parent: str | None = None,
) -> str:
    """Compute the protocol-canonical transaction ID.

    Contract:
      - one implementation is used by API, mempool, gossip, block construction,
        admission, replay, and helper planning;
      - chain_id and semantic envelope fields are committed;
      - signature encoding and local metadata are excluded; and
      - the external wire/storage form is always ``tx:<sha256-hex>``.
    """

    obj = canonical_tx_identity(
        chain_id=chain_id,
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        system=system,
        parent=parent,
    )
    return f"{TX_ID_PREFIX}{_sha256_hex(_json_canonical(obj))}"


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


def canonical_tx_identity_from_dict(chain_id: str, tx: dict[str, Any]) -> Json:
    env = TxEnvelope.from_json(tx)
    return canonical_tx_identity(
        chain_id=str(chain_id),
        tx_type=env.tx_type,
        signer=env.signer,
        nonce=int(env.nonce),
        payload=env.payload,
        system=bool(env.system),
        parent=env.parent,
    )


def compute_tx_id_from_dict(chain_id: str, tx: dict[str, Any]) -> str:
    """Compute the canonical ID from a raw transaction envelope.

    Historical aliases accepted by :class:`TxEnvelope` remain accepted, but
    malformed nonce/payload values are no longer silently normalized into a
    different transaction identity.
    """

    env = TxEnvelope.from_json(tx)
    return compute_tx_id_from_envelope(str(chain_id), env)


__all__ = [
    "TX_ID_PREFIX",
    "canonical_tx_identity",
    "canonical_tx_identity_from_dict",
    "compute_tx_id",
    "compute_tx_id_from_dict",
    "compute_tx_id_from_envelope",
]
