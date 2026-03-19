"""Types used across admission, mempool and executor.

This file is intentionally lightweight so it can be imported from both runtime
and tests without pulling heavy dependencies.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

Json = dict[str, Any]


class TxEnvelope(BaseModel):
    """Canonical tx envelope.

    Notes:
      - `sig` may be empty when signature verification is disabled (dev/test).
      - `parent` is optional and is typically auto-filled by system receipt logic.
    """

    tx_type: str
    signer: str = ""
    nonce: int = 0
    payload: Json = Field(default_factory=dict)
    sig: str = ""
    parent: str | None = None
    system: bool = False
    chain_id: str = ""

    @classmethod
    def from_any(cls, v: Any) -> TxEnvelope:
        """Best-effort conversion from dict/TxEnvelope.

        A bunch of call sites (tests, mempool, executor) pass either a raw dict or
        an already-validated TxEnvelope. This helper keeps those pathways stable.
        """

        if isinstance(v, cls):
            return v
        if isinstance(v, dict):
            # Accept a few historical aliases.
            tx_type = v.get("tx_type") or v.get("type") or v.get("name") or ""
            payload = v.get("payload") or {}
            return cls(
                tx_type=str(tx_type),
                signer=str(v.get("signer") or ""),
                nonce=int(v.get("nonce") or 0),
                payload=payload if isinstance(payload, dict) else {"value": payload},
                sig=str(v.get("sig") or ""),
                parent=v.get("parent"),
                system=bool(v.get("system") or False),
                chain_id=str(v.get("chain_id") or ""),
            )
        raise TypeError(f"cannot convert {type(v).__name__} to TxEnvelope")

    @classmethod
    def from_json(cls, v: Any) -> TxEnvelope:
        """Alias for from_any (dict -> TxEnvelope)."""
        return cls.from_any(v)

    def to_json(self) -> Json:
        return {
            "tx_type": self.tx_type,
            "signer": self.signer,
            "nonce": self.nonce,
            "payload": self.payload or {},
            "sig": self.sig,
            **({"parent": self.parent} if self.parent is not None else {}),
            **({"system": True} if self.system else {}),
            **({"chain_id": self.chain_id} if self.chain_id else {}),
        }
