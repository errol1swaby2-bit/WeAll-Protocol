from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from typing import Any, Dict, Mapping, Sequence


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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
    shared_secret: str,
    plan_id: str = "",
) -> HelperReceipt:
    normalized_tx_ids = _normalize_tx_ids(ordered_tx_ids)
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
    }
    payload = _canon_json(unsigned).encode("utf-8")
    signature = hmac.new(shared_secret.encode("utf-8"), payload, digestmod="sha256").hexdigest()
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
    )


def verify_helper_receipt(
    receipt: HelperReceipt,
    *,
    shared_secret: str,
    expected_chain_id: str,
    expected_height: int,
    expected_validator_epoch: int,
    expected_validator_set_hash: str,
    expected_parent_block_id: str,
    expected_lane_id: str,
    expected_helper_id: str,
    expected_plan_id: str = "",
    expected_ordered_tx_ids: Sequence[str] | None = None,
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

    payload = _canon_json(receipt.signing_payload()).encode("utf-8")
    expected_sig = hmac.new(shared_secret.encode("utf-8"), payload, digestmod="sha256").hexdigest()
    return hmac.compare_digest(expected_sig, receipt.signature)


__all__ = [
    "HelperReceipt",
    "sign_helper_receipt",
    "verify_helper_receipt",
]
