from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional


@dataclass(frozen=True)
class TxReject:
    code: str
    reason: str
    details: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class TxVerdict:
    ok: bool
    code: str
    reason: str
    details: Optional[Dict[str, Any]] = None

    def __iter__(self) -> Iterator[Any]:
        """Allow `ok, rej = admit_tx(...)` unpacking for tests."""
        if self.ok:
            yield True
            yield None
        else:
            yield False
            yield TxReject(self.code, self.reason, self.details)

    @staticmethod
    def admit() -> "TxVerdict":
        return TxVerdict(True, "ok", "admitted", None)

    @staticmethod
    def reject(code: str, reason: str, details: Optional[Dict[str, Any]] = None) -> "TxVerdict":
        return TxVerdict(False, code, reason, details)


@dataclass(frozen=True)
class TxEnvelope:
    tx_type: str
    signer: str
    nonce: int
    payload: Dict[str, Any]
    sig: str = ""
    parent: Optional[str] = None
    system: bool = False

    @staticmethod
    def from_json(j: Any) -> "TxEnvelope":
        if isinstance(j, TxEnvelope):
            return j
        if not isinstance(j, dict):
            j = dict(j)  # type: ignore[arg-type]
        return TxEnvelope(
            tx_type=str(j.get("tx_type", "")),
            signer=str(j.get("signer", "")),
            nonce=int(j.get("nonce", 0)),
            payload=dict(j.get("payload", {}) or {}),
            sig=str(j.get("sig", "") or ""),
            parent=(None if j.get("parent") is None else str(j.get("parent"))),
            system=bool(j.get("system", False)),
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "tx_type": self.tx_type,
            "signer": self.signer,
            "nonce": self.nonce,
            "payload": self.payload,
            "sig": self.sig,
            "parent": self.parent,
            "system": self.system,
        }
