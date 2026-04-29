from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import HelperExecutionCertificate, make_namespace_hash, sign_helper_certificate
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint, plan_parallel_execution


def pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def lane_setup(*, txs, validators=("v1", "v2", "v3"), validator_set_hash="vhash", view=7, leader_id="v1"):
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=list(validators),
        validator_set_hash=validator_set_hash,
        view=view,
        leader_id=leader_id,
    )
    plan_id = canonical_lane_plan_fingerprint(lane_plans)
    return lane_plans, plan_id


def first_helper_lane(lane_plans: tuple[LanePlan, ...]) -> LanePlan:
    return next(plan for plan in lane_plans if str(plan.helper_id or ""))


def dispatch_context(*, plan_id="", manifest_hash="", manifest_payload=None, coordinator_pubkey="", manifest_signature_required=False):
    return HelperDispatchContext(
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
        plan_id=str(plan_id or ""),
        manifest_hash=str(manifest_hash or ""),
        manifest_payload=manifest_payload,
        coordinator_pubkey=str(coordinator_pubkey or ""),
        manifest_signature_required=bool(manifest_signature_required),
    )


def signed_lane_certificate(
    *,
    lane_plan: LanePlan,
    seed_byte: int,
    plan_id: str = "",
    receipts_root: str = "receipts",
    lane_delta_hash: str = "delta",
    manifest_hash: str = "",
    helper_id: str | None = None,
    tx_ids: tuple[str, ...] | None = None,
    chain_id: str = "c1",
    block_height: int = 22,
    view: int = 7,
    leader_id: str = "v1",
    validator_epoch: int = 9,
    validator_set_hash: str = "vhash",
):
    helper_id2 = str(helper_id or lane_plan.helper_id or "")
    tx_ids2 = tuple(tx_ids if tx_ids is not None else lane_plan.tx_ids)
    seed = (bytes([seed_byte]) * 32).hex()
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id=chain_id,
            block_height=block_height,
            view=view,
            leader_id=leader_id,
            helper_id=helper_id2,
            validator_epoch=validator_epoch,
            validator_set_hash=validator_set_hash,
            lane_id=str(lane_plan.lane_id),
            tx_ids=tx_ids2,
            tx_order_hash="order",
            receipts_root=receipts_root,
            write_set_hash="writes",
            read_set_hash="reads",
            lane_delta_hash=lane_delta_hash,
            namespace_hash=make_namespace_hash(lane_plan.namespace_prefixes),
            plan_id=str(plan_id or ""),
            manifest_hash=str(manifest_hash or ""),
        ),
        privkey=seed,
    )
    return cert, pub_hex_from_seed(seed)
