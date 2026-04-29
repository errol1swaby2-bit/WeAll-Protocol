from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Dict, Mapping, Sequence

import binascii

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .helper_planner import HelperPlan, build_helper_plan, canonicalize_txs, stable_tx_id
from .helper_receipts import HelperReceipt, sign_helper_receipt, verify_helper_receipt


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LaneExecutionResult:
    lane_id: str
    ordered_tx_ids: tuple[str, ...]
    input_state_hash: str
    output_state_hash: str
    post_state: Dict[str, Any]
    helper_id: str
    receipt: HelperReceipt
    plan_id: str = ""


class HelperExecutionError(Exception):
    pass


class HelperExecutor:
    """
    Minimal deterministic helper executor used by helper tests.

    Production helper trust boundaries use asymmetric helper identities. This
    test harness still supports legacy shared secrets only when explicitly
    provided, so old corpus-style tests can be ported gradually without
    weakening runtime verification paths.
    """

    def __init__(
        self,
        helper_signing_material: Mapping[str, str],
        *,
        helper_pubkeys: Mapping[str, str] | None = None,
        legacy_shared_secret_mode: bool = False,
    ):
        self.helper_signing_material = {str(k): v for k, v in dict(helper_signing_material).items()}
        self.helper_pubkeys = {str(k): str(v) for k, v in dict(helper_pubkeys or {}).items()}
        self.legacy_shared_secret_mode = bool(legacy_shared_secret_mode)
        self._helper_legacy_mode_by_id: dict[str, bool] = {}
        derived: dict[str, str] = {}
        for helper_id, material in self.helper_signing_material.items():
            if self.legacy_shared_secret_mode:
                self._helper_legacy_mode_by_id[helper_id] = True
                continue
            if isinstance(material, Ed25519PrivateKey):
                key_obj = material
                self._helper_legacy_mode_by_id[helper_id] = False
                derived[helper_id] = key_obj.public_key().public_bytes_raw().hex()
                continue
            try:
                raw = bytes.fromhex(str(material))
                if len(raw) != 32:
                    raise ValueError("ed25519 private key must be 32 bytes")
                key_obj = Ed25519PrivateKey.from_private_bytes(raw)
                self._helper_legacy_mode_by_id[helper_id] = False
                derived[helper_id] = key_obj.public_key().public_bytes_raw().hex()
            except (ValueError, TypeError, binascii.Error):
                self._helper_legacy_mode_by_id[helper_id] = True
        for helper_id, pubkey in derived.items():
            self.helper_pubkeys.setdefault(helper_id, pubkey)

    def plan(
        self,
        *,
        chain_id: str,
        height: int,
        parent_block_id: str,
        validator_epoch: int,
        validators: Sequence[str],
        txs: Sequence[Mapping[str, Any]],
    ) -> HelperPlan:
        return build_helper_plan(
            chain_id=chain_id,
            height=height,
            parent_block_id=parent_block_id,
            validator_epoch=validator_epoch,
            validators=validators,
            txs=txs,
        )

    def _apply_tx(self, state: Dict[str, Any], tx: Mapping[str, Any]) -> Dict[str, Any]:
        new_state = json.loads(_canon_json(state))
        balances = dict(new_state.get("balances", {}))
        nonces = dict(new_state.get("nonces", {}))

        signer = str(tx.get("signer", ""))
        delta = int(tx.get("delta", 0) or 0)
        nonce = int(tx.get("nonce", 0) or 0)

        current_nonce = int(nonces.get(signer, 0) or 0)
        if nonce != current_nonce + 1:
            raise HelperExecutionError(
                f"nonce mismatch for signer={signer}: got {nonce}, expected {current_nonce + 1}"
            )

        balances[signer] = int(balances.get(signer, 0) or 0) + delta
        nonces[signer] = nonce

        new_state["balances"] = balances
        new_state["nonces"] = nonces
        return new_state

    def execute_lane(
        self,
        *,
        chain_id: str,
        height: int,
        parent_block_id: str,
        validator_epoch: int,
        validator_set_hash: str,
        lane_id: str,
        helper_id: str,
        state: Mapping[str, Any],
        lane_txs: Sequence[Mapping[str, Any]],
        plan_id: str = "",
    ) -> LaneExecutionResult:
        if helper_id not in self.helper_signing_material:
            raise HelperExecutionError(f"missing helper signing material for helper_id={helper_id}")

        ordered = canonicalize_txs(lane_txs)
        ordered_tx_ids = tuple(stable_tx_id(tx) for tx in ordered)
        input_state_hash = _sha256_hex(state)

        post_state: Dict[str, Any] = json.loads(_canon_json(state))
        for tx in ordered:
            post_state = self._apply_tx(post_state, tx)

        output_state_hash = _sha256_hex(post_state)
        receipt_kwargs = {
            "chain_id": chain_id,
            "height": height,
            "validator_epoch": validator_epoch,
            "validator_set_hash": validator_set_hash,
            "parent_block_id": parent_block_id,
            "lane_id": lane_id,
            "ordered_tx_ids": ordered_tx_ids,
            "input_state_hash": input_state_hash,
            "output_state_hash": output_state_hash,
            "helper_id": helper_id,
            "plan_id": str(plan_id or ""),
        }
        if self._helper_legacy_mode_by_id.get(helper_id, self.legacy_shared_secret_mode):
            receipt = sign_helper_receipt(
                **receipt_kwargs,
                shared_secret=str(self.helper_signing_material[helper_id]),
                allow_legacy_shared_secret=True,
            )
        else:
            receipt = sign_helper_receipt(
                **receipt_kwargs,
                privkey=self.helper_signing_material[helper_id],
            )
        return LaneExecutionResult(
            lane_id=lane_id,
            ordered_tx_ids=ordered_tx_ids,
            input_state_hash=input_state_hash,
            output_state_hash=output_state_hash,
            post_state=post_state,
            helper_id=helper_id,
            receipt=receipt,
            plan_id=str(plan_id or ""),
        )

    def verify_lane_result(
        self,
        lane_result: LaneExecutionResult,
        *,
        chain_id: str,
        height: int,
        validator_epoch: int,
        validator_set_hash: str,
        parent_block_id: str,
        expected_plan_id: str = "",
    ) -> bool:
        if self._helper_legacy_mode_by_id.get(lane_result.helper_id, self.legacy_shared_secret_mode):
            secret = self.helper_signing_material.get(lane_result.helper_id)
            if not secret:
                return False
            return verify_helper_receipt(
                lane_result.receipt,
                shared_secret=str(secret),
                allow_legacy_shared_secret=True,
                expected_chain_id=chain_id,
                expected_height=height,
                expected_validator_epoch=validator_epoch,
                expected_validator_set_hash=validator_set_hash,
                expected_parent_block_id=parent_block_id,
                expected_lane_id=lane_result.lane_id,
                expected_helper_id=lane_result.helper_id,
                expected_plan_id=str(expected_plan_id or lane_result.plan_id or ""),
            )
        helper_pubkey = self.helper_pubkeys.get(lane_result.helper_id)
        if not helper_pubkey:
            return False
        return verify_helper_receipt(
            lane_result.receipt,
            helper_pubkey=helper_pubkey,
            expected_chain_id=chain_id,
            expected_height=height,
            expected_validator_epoch=validator_epoch,
            expected_validator_set_hash=validator_set_hash,
            expected_parent_block_id=parent_block_id,
            expected_lane_id=lane_result.lane_id,
            expected_helper_id=lane_result.helper_id,
            expected_plan_id=str(expected_plan_id or lane_result.plan_id or ""),
        )

    def merge_lane_results(
        self,
        lane_results: Sequence[LaneExecutionResult],
        *,
        base_state: Mapping[str, Any],
    ) -> Dict[str, Any]:
        merged = json.loads(_canon_json(base_state))
        merged_balances = dict(merged.get("balances", {}))
        merged_nonces = dict(merged.get("nonces", {}))
        touched_keys = set()

        for lane_result in sorted(lane_results, key=lambda lr: lr.lane_id):
            balances = lane_result.post_state.get("balances", {})
            nonces = lane_result.post_state.get("nonces", {})

            base_balances = dict(base_state.get("balances", {}))
            base_nonces = dict(base_state.get("nonces", {}))

            changed_signers = sorted(
                {str(k) for k, v in balances.items() if base_balances.get(k) != v}
                | {str(k) for k, v in nonces.items() if base_nonces.get(k) != v}
            )

            for signer in changed_signers:
                touch_key = f"signer:{signer}"
                if touch_key in touched_keys:
                    raise HelperExecutionError(
                        f"non-independent lane merge conflict for signer={signer}"
                    )
                touched_keys.add(touch_key)
                if signer in balances:
                    merged_balances[signer] = balances[signer]
                if signer in nonces:
                    merged_nonces[signer] = nonces[signer]

        merged["balances"] = merged_balances
        merged["nonces"] = merged_nonces
        return merged

    def fallback_execute_lane(
        self,
        *,
        chain_id: str,
        height: int,
        parent_block_id: str,
        validator_epoch: int,
        validator_set_hash: str,
        lane_id: str,
        helper_id: str,
        state: Mapping[str, Any],
        lane_txs: Sequence[Mapping[str, Any]],
        plan_id: str = "",
    ):
        return self.execute_lane(
            chain_id=chain_id,
            height=height,
            parent_block_id=parent_block_id,
            validator_epoch=validator_epoch,
            validator_set_hash=validator_set_hash,
            lane_id=lane_id,
            helper_id=helper_id,
            state=state,
            lane_txs=lane_txs,
            plan_id=plan_id,
        )
