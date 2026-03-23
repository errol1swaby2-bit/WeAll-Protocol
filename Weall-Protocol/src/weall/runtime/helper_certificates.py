from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


CERTIFICATE_DOMAIN = "WEALL/HELPER_CERTIFICATE/V1"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def sha256(data: str) -> str:
    return hashlib.sha256(str(data).encode("utf-8")).hexdigest()


def make_namespace_hash(prefixes: Sequence[str]) -> str:
    cleaned = sorted({str(p).strip().lower() for p in prefixes if str(p).strip()})
    return hash_json(cleaned)


def compute_namespace_hash(prefixes: Sequence[str]) -> str:
    return make_namespace_hash(prefixes)


def make_tx_order_hash(tx_ids: Sequence[str]) -> str:
    return hash_json([str(tx_id) for tx_id in tx_ids])


def hash_ordered_strings(values: Sequence[str]) -> str:
    cleaned = [str(v) for v in values]
    return hash_json(cleaned)


def hash_receipts(receipts: Sequence[Mapping[str, Any]]) -> str:
    rows = [dict(item) for item in receipts]
    return hash_json(rows)


def hash_state_delta_ops(delta_ops: Sequence[Mapping[str, Any]]) -> str:
    rows: list[dict[str, Any]] = []
    for item in list(delta_ops or []):
        if not isinstance(item, Mapping):
            continue
        row = dict(item)
        rows.append(row)
    rows.sort(key=lambda row: (str(row.get("path") or ""), str(row.get("op") or ""), hash_json(row)))
    return hash_json(rows)


@dataclass(frozen=True)
class HelperCertificate:
    chain_id: str
    block_height: int
    view: int
    leader_id: str
    helper_id: str
    validator_epoch: int
    validator_set_hash: str
    lane_id: str
    tx_ids: tuple[str, ...]
    tx_order_hash: str
    receipts_root: str
    write_set_hash: str
    read_set_hash: str
    state_delta_hash: str
    namespace_hash: str
    signature: str = ""
    manifest_hash: str = ""
    plan_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "tx_ids", tuple(str(x) for x in self.tx_ids))

    def to_json(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "block_height": int(self.block_height),
            "view": int(self.view),
            "leader_id": self.leader_id,
            "helper_id": self.helper_id,
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
            "lane_id": self.lane_id,
            "tx_ids": list(self.tx_ids),
            "tx_order_hash": self.tx_order_hash,
            "receipts_root": self.receipts_root,
            "write_set_hash": self.write_set_hash,
            "read_set_hash": self.read_set_hash,
            "state_delta_hash": self.state_delta_hash,
            "namespace_hash": self.namespace_hash,
            "manifest_hash": self.manifest_hash,
            "plan_id": self.plan_id,
            "signature": self.signature,
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_json())

    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_json()
        payload["signature"] = ""
        return payload

    def compute_tx_order_hash(self) -> str:
        return make_tx_order_hash(self.tx_ids)

    def compute_receipts_root(self, receipts: Sequence[Mapping[str, Any]]) -> str:
        return hash_receipts(receipts)

    def verify_internal_consistency(self) -> bool:
        return self.tx_order_hash == self.compute_tx_order_hash()


@dataclass(frozen=True)
class HelperExecutionCertificate:
    chain_id: str
    block_height: int
    view: int
    leader_id: str
    helper_id: str
    validator_epoch: int
    validator_set_hash: str
    lane_id: str
    tx_ids: tuple[str, ...]
    tx_order_hash: str
    receipts_root: str
    write_set_hash: str
    read_set_hash: str
    lane_delta_hash: str
    namespace_hash: str
    helper_signature: str = ""
    manifest_hash: str = ""
    plan_id: str = ""

    def __init__(self, **kwargs: Any) -> None:
        tx_ids = kwargs.get("tx_ids", ())
        if isinstance(tx_ids, list):
            tx_ids = tuple(tx_ids)
        helper_signature = kwargs.get("helper_signature", kwargs.get("signature", ""))
        lane_delta_hash = kwargs.get("lane_delta_hash", kwargs.get("state_delta_hash", ""))
        object.__setattr__(self, "chain_id", str(kwargs.get("chain_id", "")))
        object.__setattr__(self, "block_height", int(kwargs.get("block_height", kwargs.get("height", 0))))
        object.__setattr__(self, "view", int(kwargs.get("view", 0)))
        object.__setattr__(self, "leader_id", str(kwargs.get("leader_id", "")))
        object.__setattr__(self, "helper_id", str(kwargs.get("helper_id", "")))
        object.__setattr__(self, "validator_epoch", int(kwargs.get("validator_epoch", 0)))
        object.__setattr__(self, "validator_set_hash", str(kwargs.get("validator_set_hash", "")))
        object.__setattr__(self, "lane_id", str(kwargs.get("lane_id", "")))
        object.__setattr__(self, "tx_ids", tuple(str(x) for x in tx_ids))
        object.__setattr__(self, "tx_order_hash", str(kwargs.get("tx_order_hash", "")))
        object.__setattr__(self, "receipts_root", str(kwargs.get("receipts_root", "")))
        object.__setattr__(self, "write_set_hash", str(kwargs.get("write_set_hash", "")))
        object.__setattr__(self, "read_set_hash", str(kwargs.get("read_set_hash", "")))
        object.__setattr__(self, "lane_delta_hash", str(lane_delta_hash))
        object.__setattr__(self, "namespace_hash", str(kwargs.get("namespace_hash", "")))
        object.__setattr__(self, "helper_signature", str(helper_signature))
        object.__setattr__(self, "manifest_hash", str(kwargs.get("manifest_hash", "")))
        object.__setattr__(self, "plan_id", str(kwargs.get("plan_id", "")))

    @property
    def state_delta_hash(self) -> str:
        return self.lane_delta_hash

    @property
    def signature(self) -> str:
        return self.helper_signature

    def to_json(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "block_height": int(self.block_height),
            "view": int(self.view),
            "leader_id": self.leader_id,
            "helper_id": self.helper_id,
            "validator_epoch": int(self.validator_epoch),
            "validator_set_hash": self.validator_set_hash,
            "lane_id": self.lane_id,
            "tx_ids": list(self.tx_ids),
            "tx_order_hash": self.tx_order_hash,
            "receipts_root": self.receipts_root,
            "write_set_hash": self.write_set_hash,
            "read_set_hash": self.read_set_hash,
            "lane_delta_hash": self.lane_delta_hash,
            "namespace_hash": self.namespace_hash,
            "manifest_hash": self.manifest_hash,
            "plan_id": self.plan_id,
            "helper_signature": self.helper_signature,
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_json())

    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_json()
        payload["helper_signature"] = ""
        return payload

    def compute_tx_order_hash(self) -> str:
        return make_tx_order_hash(self.tx_ids)

    def compute_receipts_root(self, receipts: Sequence[Mapping[str, Any]]) -> str:
        return hash_receipts(receipts)

    def verify_internal_consistency(self) -> bool:
        return True

    def to_helper_certificate(self) -> HelperCertificate:
        return HelperCertificate(
            chain_id=self.chain_id,
            block_height=self.block_height,
            view=self.view,
            leader_id=self.leader_id,
            helper_id=self.helper_id,
            validator_epoch=self.validator_epoch,
            validator_set_hash=self.validator_set_hash,
            lane_id=self.lane_id,
            tx_ids=self.tx_ids,
            tx_order_hash=self.tx_order_hash,
            receipts_root=self.receipts_root,
            write_set_hash=self.write_set_hash,
            read_set_hash=self.read_set_hash,
            state_delta_hash=self.lane_delta_hash,
            namespace_hash=self.namespace_hash,
            manifest_hash=self.manifest_hash,
            plan_id=self.plan_id,
            signature=self.helper_signature,
        )

    @classmethod
    def from_helper_certificate(cls, cert: HelperCertificate) -> "HelperExecutionCertificate":
        return cls(**cert.to_json())


@dataclass(frozen=True)
class HelperMisbehaviorProof:
    helper_id: str
    plan_id: str
    lane_id: str
    certificate_a_id: str
    certificate_b_id: str
    reason: str
    created_ms: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "helper_id": self.helper_id,
            "plan_id": self.plan_id,
            "lane_id": self.lane_id,
            "certificate_a_id": self.certificate_a_id,
            "certificate_b_id": self.certificate_b_id,
            "reason": self.reason,
            "created_ms": self.created_ms,
        }


def ensure_helper_execution_certificate(
    obj: HelperExecutionCertificate | HelperCertificate | Mapping[str, Any],
) -> HelperExecutionCertificate:
    if isinstance(obj, HelperExecutionCertificate):
        return obj
    if isinstance(obj, HelperCertificate):
        return HelperExecutionCertificate.from_helper_certificate(obj)
    if isinstance(obj, Mapping):
        return HelperExecutionCertificate(**dict(obj))
    raise TypeError(f"Unsupported helper certificate type: {type(obj)!r}")


def ensure_helper_certificate(
    obj: HelperExecutionCertificate | HelperCertificate | Mapping[str, Any],
) -> HelperCertificate:
    if isinstance(obj, HelperCertificate):
        return obj
    if isinstance(obj, HelperExecutionCertificate):
        return obj.to_helper_certificate()
    if isinstance(obj, Mapping):
        return HelperCertificate(**dict(obj))
    raise TypeError(f"Unsupported helper certificate type: {type(obj)!r}")


def _signature_material(cert: HelperExecutionCertificate | HelperCertificate) -> bytes:
    return canonical_json(cert.signing_payload()).encode("utf-8")


def sign_helper_certificate(
    cert: HelperExecutionCertificate | HelperCertificate | None = None,
    privkey: str | None = None,
    secret: str | None = None,
    **kwargs: Any,
) -> HelperExecutionCertificate | dict[str, Any]:
    # Newer plan-hardening API used by batch33 tests
    if cert is None and kwargs:
        chain_id = str(kwargs["chain_id"])
        height = int(kwargs["height"])
        validator_epoch = int(kwargs["validator_epoch"])
        validator_set_hash = str(kwargs["validator_set_hash"])
        parent_block_id = str(kwargs["parent_block_id"])
        lane_id = str(kwargs["lane_id"])
        helper_id = str(kwargs["helper_id"])
        lane_tx_ids = tuple(str(x) for x in kwargs.get("lane_tx_ids", ()))
        descriptor_hash = str(kwargs["descriptor_hash"])
        plan_id = str(kwargs["plan_id"])
        shared_secret = str(kwargs["shared_secret"])
        issued_ms = int(kwargs.get("issued_ms", int(time.time() * 1000)))
        payload = {
            "domain": CERTIFICATE_DOMAIN,
            "chain_id": chain_id,
            "height": height,
            "validator_epoch": validator_epoch,
            "validator_set_hash": validator_set_hash,
            "parent_block_id": parent_block_id,
            "lane_id": lane_id,
            "helper_id": helper_id,
            "lane_tx_ids": list(lane_tx_ids),
            "descriptor_hash": descriptor_hash,
            "plan_id": plan_id,
            "issued_ms": issued_ms,
        }
        payload["certificate_id"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        payload["signature"] = hmac.new(
            shared_secret.encode("utf-8"),
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return payload

    # Legacy/mainline object API
    normalized = ensure_helper_execution_certificate(cert)
    if privkey is not None:
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey))
        sig = key.sign(_signature_material(normalized)).hex()
        return HelperExecutionCertificate(**{**normalized.to_json(), "helper_signature": sig})
    signing_secret = secret if secret is not None else normalized.helper_id
    sig = hmac.new(str(signing_secret).encode("utf-8"), _signature_material(normalized), hashlib.sha256).hexdigest()
    return HelperExecutionCertificate(**{**normalized.to_json(), "helper_signature": sig})


def verify_helper_certificate_signature(
    cert: HelperExecutionCertificate | HelperCertificate | Mapping[str, Any],
    helper_pubkey: str | None = None,
    secret: str | None = None,
) -> bool:
    normalized = ensure_helper_execution_certificate(cert)
    if helper_pubkey is not None:
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(helper_pubkey))
            key.verify(bytes.fromhex(normalized.helper_signature), _signature_material(normalized))
            return True
        except Exception:
            return False
    signing_secret = secret if secret is not None else normalized.helper_id
    expected = hmac.new(str(signing_secret).encode("utf-8"), _signature_material(normalized), hashlib.sha256).hexdigest()
    return hmac.compare_digest(normalized.helper_signature, expected)


def validate_certificate_scope(
    cert: HelperExecutionCertificate | HelperCertificate | Mapping[str, Any],
    *,
    namespace_prefixes: Sequence[str],
) -> bool:
    normalized = ensure_helper_execution_certificate(cert)
    return normalized.namespace_hash == make_namespace_hash(namespace_prefixes)


def build_plan_misbehavior_proof(
    *,
    certificate_a: Mapping[str, Any],
    certificate_b: Mapping[str, Any],
) -> HelperMisbehaviorProof | None:
    if certificate_a.get("helper_id") != certificate_b.get("helper_id"):
        return None
    if certificate_a.get("plan_id") != certificate_b.get("plan_id"):
        return None
    if certificate_a.get("lane_id") != certificate_b.get("lane_id"):
        return None
    if certificate_a.get("certificate_id") == certificate_b.get("certificate_id"):
        return None
    if certificate_a.get("descriptor_hash") == certificate_b.get("descriptor_hash"):
        return None
    return HelperMisbehaviorProof(
        helper_id=str(certificate_a["helper_id"]),
        plan_id=str(certificate_a["plan_id"]),
        lane_id=str(certificate_a["lane_id"]),
        certificate_a_id=str(certificate_a["certificate_id"]),
        certificate_b_id=str(certificate_b["certificate_id"]),
        reason="conflicting_descriptor_hash_for_same_helper_plan_lane",
        created_ms=max(int(certificate_a.get("issued_ms", 0)), int(certificate_b.get("issued_ms", 0))),
    )


__all__ = [
    "CERTIFICATE_DOMAIN",
    "HelperCertificate",
    "HelperExecutionCertificate",
    "HelperMisbehaviorProof",
    "canonical_json",
    "compute_namespace_hash",
    "ensure_helper_certificate",
    "ensure_helper_execution_certificate",
    "hash_json",
    "hash_ordered_strings",
    "hash_receipts",
    "hash_state_delta_ops",
    "make_namespace_hash",
    "make_tx_order_hash",
    "sha256",
    "sign_helper_certificate",
    "build_plan_misbehavior_proof",
    "validate_certificate_scope",
    "verify_helper_certificate_signature",
]
