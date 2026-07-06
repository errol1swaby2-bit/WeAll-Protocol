from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from typing import Any, Dict, Mapping, Sequence
from weall.runtime.json_tools import canonical_json_str as _canon_json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from weall.crypto.sig import sign_signature_for_profile, verify_signature_for_profile
from weall.crypto.signature_profiles import LEGACY_ED25519_V1, default_signature_profile_for_mode, normalize_signature_profile_id



def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


def _normalize_tx_ids(values: Sequence[str] | None) -> tuple[str, ...]:
    return tuple(str(v) for v in tuple(values or ()))


@dataclass(frozen=True)
class HelperReceipt:
    chain_id: str
    height: int
    validator_epoch: int
    validator_set_hash: str
    parent_block_id: str
    lane_id: str
    ordered_tx_ids: tuple[str, ...]
    input_state_hash: str
    output_state_hash: str
    helper_id: str
    signature: str
    plan_id: str = ""
    sig_profile: str = LEGACY_ED25519_V1

    def signing_payload(self) -> Dict[str, Any]:
        return {
            "t": "HELPER_RECEIPT",
            "chain_id": self.chain_id,
            "height": self.height,
            "validator_epoch": self.validator_epoch,
            "validator_set_hash": self.validator_set_hash,
            "parent_block_id": self.parent_block_id,
            "lane_id": self.lane_id,
            "ordered_tx_ids": list(self.ordered_tx_ids),
            "input_state_hash": self.input_state_hash,
            "output_state_hash": self.output_state_hash,
            "helper_id": self.helper_id,
            "plan_id": self.plan_id,
            "sig_profile": normalize_signature_profile_id(self.sig_profile) or LEGACY_ED25519_V1,
        }

    def receipt_id(self) -> str:
        return _sha256_hex(self.signing_payload())

    def context_fingerprint(self) -> str:
        return _sha256_hex(
            {
                "chain_id": self.chain_id,
                "height": int(self.height),
                "validator_epoch": int(self.validator_epoch),
                "validator_set_hash": self.validator_set_hash,
                "parent_block_id": self.parent_block_id,
                "lane_id": self.lane_id,
                "ordered_tx_ids": list(self.ordered_tx_ids),
                "helper_id": self.helper_id,
                "plan_id": self.plan_id,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        payload = self.signing_payload()
        payload["signature"] = self.signature
        return payload


def _signing_material(unsigned: Mapping[str, Any]) -> bytes:
    return _canon_json(dict(unsigned)).encode("utf-8")


def _private_key_from_value(value: str | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(str(value)))


def _public_key_from_value(value: str | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(value)))


def sign_helper_receipt(
    *,
    chain_id: str,
    height: int,
    validator_epoch: int,
    validator_set_hash: str,
    parent_block_id: str,
    lane_id: str,
    ordered_tx_ids: Sequence[str],
    input_state_hash: str,
    output_state_hash: str,
    helper_id: str,
    plan_id: str = "",
    privkey: str | Ed25519PrivateKey | None = None,
    receipt_secret: str | None = None,
    allow_legacy_receipt_secret: bool = False,
    sig_profile: str | None = None,
) -> HelperReceipt:
    normalized_tx_ids = _normalize_tx_ids(ordered_tx_ids)
    profile = normalize_signature_profile_id(sig_profile) or default_signature_profile_for_mode()
    if receipt_secret is not None and privkey is None:
        profile = "legacy-hmac-helper-secret-v1"
    unsigned = {
        "t": "HELPER_RECEIPT",
        "chain_id": str(chain_id),
        "height": int(height),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash),
        "parent_block_id": str(parent_block_id),
        "lane_id": str(lane_id),
        "ordered_tx_ids": list(normalized_tx_ids),
        "input_state_hash": str(input_state_hash),
        "output_state_hash": str(output_state_hash),
        "helper_id": str(helper_id),
        "plan_id": str(plan_id or ""),
        "sig_profile": profile,
    }
    payload = _signing_material(unsigned)
    if privkey is not None:
        if isinstance(privkey, Ed25519PrivateKey):
            if profile != LEGACY_ED25519_V1:
                raise ValueError("ed25519 private key object requires legacy-ed25519-v1 helper receipt profile")
            signature = privkey.sign(payload).hex()
        else:
            signature = sign_signature_for_profile(sig_profile=profile, message=payload, privkey=str(privkey), encoding="hex")
    else:
        if not allow_legacy_receipt_secret or receipt_secret is None:
            raise ValueError("helper receipt signing requires privkey; legacy HMAC receipt signing is disabled unless explicitly allowed")
        signature = hmac.new(receipt_secret.encode("utf-8"), payload, digestmod="sha256").hexdigest()
    return HelperReceipt(
        chain_id=str(chain_id),
        height=int(height),
        validator_epoch=int(validator_epoch),
        validator_set_hash=str(validator_set_hash),
        parent_block_id=str(parent_block_id),
        lane_id=str(lane_id),
        ordered_tx_ids=normalized_tx_ids,
        input_state_hash=str(input_state_hash),
        output_state_hash=str(output_state_hash),
        helper_id=str(helper_id),
        signature=signature,
        plan_id=str(plan_id or ""),
        sig_profile=profile,
    )


def verify_helper_receipt(
    receipt: HelperReceipt,
    *,
    expected_chain_id: str,
    expected_height: int,
    expected_validator_epoch: int,
    expected_validator_set_hash: str,
    expected_parent_block_id: str,
    expected_lane_id: str,
    expected_helper_id: str,
    expected_plan_id: str = "",
    expected_ordered_tx_ids: Sequence[str] | None = None,
    helper_pubkey: str | Ed25519PublicKey | None = None,
    receipt_secret: str | None = None,
    allow_legacy_receipt_secret: bool = False,
    sig_profile: str | None = None,
) -> bool:
    if receipt.chain_id != str(expected_chain_id):
        return False
    if int(receipt.height) != int(expected_height):
        return False
    if int(receipt.validator_epoch) != int(expected_validator_epoch):
        return False
    if receipt.validator_set_hash != str(expected_validator_set_hash):
        return False
    if receipt.parent_block_id != str(expected_parent_block_id):
        return False
    if receipt.lane_id != str(expected_lane_id):
        return False
    if receipt.helper_id != str(expected_helper_id):
        return False
    if str(expected_plan_id or "") != str(receipt.plan_id or ""):
        return False
    if expected_ordered_tx_ids is not None and receipt.ordered_tx_ids != _normalize_tx_ids(expected_ordered_tx_ids):
        return False

    payload = _signing_material(receipt.signing_payload())
    if helper_pubkey is not None:
        profile = normalize_signature_profile_id(sig_profile or getattr(receipt, "sig_profile", "")) or LEGACY_ED25519_V1
        if isinstance(helper_pubkey, Ed25519PublicKey):
            if profile != LEGACY_ED25519_V1:
                return False
            try:
                helper_pubkey.verify(bytes.fromhex(receipt.signature), payload)
                return True
            except Exception:
                return False
        return verify_signature_for_profile(sig_profile=profile, message=payload, sig=receipt.signature, pubkey=str(helper_pubkey))
    if not allow_legacy_receipt_secret or receipt_secret is None:
        return False
    expected_sig = hmac.new(receipt_secret.encode("utf-8"), payload, digestmod="sha256").hexdigest()
    return hmac.compare_digest(expected_sig, receipt.signature)


__all__ = [
    "HelperReceipt",
    "sign_helper_receipt",
    "verify_helper_receipt",
]
