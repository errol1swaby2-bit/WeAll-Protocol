from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.runtime.block_hash import (
    compute_block_hash,
    compute_helper_execution_root,
    compute_receipts_root,
)
from weall.runtime.block_id import compute_block_id
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_id import compute_tx_id_from_envelope

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ReceivedBlockCommitmentBinding:
    tx_ids: tuple[str, ...]
    block_id: str
    block_hash: str
    advertised_block_hash: str


def validate_received_block_commitments(
    *,
    block: Json,
    chain_id: str,
) -> tuple[bool, str, ReceivedBlockCommitmentBinding | None]:
    """Rebind all consensus identity commitments from received block contents.

    This validator is intentionally side-effect free.  It makes the ordered body
    transaction semantics authoritative, then requires every advertised identity
    commitment to match that canonical derivation before replay or BFT voting.
    Receipt *contents* are replay-verified separately; this stage binds the block
    ID to the advertised receipts root so a supplied alias cannot enter caches or
    ancestry state before full execution verifies that root.
    """

    if not isinstance(block, dict):
        return False, "not_object", None
    header = block.get("header")
    if not isinstance(header, dict):
        return False, "missing_header", None
    if str(header.get("chain_id") or "").strip() != str(chain_id):
        return False, "chain_id_mismatch", None

    txs = block.get("txs")
    if not isinstance(txs, list):
        return False, "txs", None

    canonical_tx_ids: list[str] = []
    for index, raw in enumerate(txs):
        if not isinstance(raw, dict):
            return False, f"tx_identity_invalid:{index}", None
        try:
            env = TxEnvelope.from_json(raw)
            canonical_tx_id = compute_tx_id_from_envelope(str(chain_id), env)
        except Exception:
            return False, f"tx_identity_invalid:{index}", None

        advertised_tx_id = str(raw.get("tx_id") or "").strip()
        if advertised_tx_id and advertised_tx_id != canonical_tx_id:
            return False, f"body_tx_id_mismatch:{index}", None
        canonical_tx_ids.append(canonical_tx_id)

    advertised_header_ids = header.get("tx_ids")
    if not isinstance(advertised_header_ids, list):
        return False, "header_tx_ids_missing", None
    normalized_header_ids = [str(value or "").strip() for value in advertised_header_ids]
    if normalized_header_ids != canonical_tx_ids:
        return False, "header_tx_ids_mismatch", None

    # Block identity is derived from the block's own advertised parent. Whether
    # that parent is the receiver's admissible current parent is a separate chain
    # position check performed by the caller. Keeping these concerns separate is
    # important for speculative BFT branches and for deterministic content identity.
    canonical_prev_block_id = str(block.get("prev_block_id") or "").strip()

    receipts_root = str(header.get("receipts_root") or "").strip()
    if not receipts_root:
        return False, "missing_receipts_root", None

    try:
        height = int(header.get("height") or block.get("height") or 0)
        ts_ms = int(header.get("block_ts_ms") or block.get("block_ts_ms") or 0)
    except Exception:
        return False, "identity_fields_invalid", None
    if height <= 0 or ts_ms <= 0:
        return False, "identity_fields_invalid", None

    expected_block_id = compute_block_id(
        chain_id=str(chain_id),
        height=height,
        prev_block_id=canonical_prev_block_id,
        prev_block_hash=str(header.get("prev_block_hash") or ""),
        ts_ms=ts_ms,
        node_id=str(block.get("proposer") or block.get("node_id") or ""),
        tx_ids=canonical_tx_ids,
        receipts_root=receipts_root,
    )
    advertised_block_id = str(block.get("block_id") or "").strip()
    if advertised_block_id and advertised_block_id != expected_block_id:
        return False, "block_id_mismatch", None

    expected_block_hash = compute_block_hash(header=header)
    advertised_block_hash = str(block.get("block_hash") or "").strip()

    return (
        True,
        "ok",
        ReceivedBlockCommitmentBinding(
            tx_ids=tuple(canonical_tx_ids),
            block_id=expected_block_id,
            block_hash=expected_block_hash,
            advertised_block_hash=advertised_block_hash,
        ),
    )


def validate_complete_block_commitments(
    *,
    block: Json,
    chain_id: str,
) -> tuple[bool, str, ReceivedBlockCommitmentBinding | None]:
    """Validate the complete canonical block object used for durable/trusted storage.

    Ordinary BFT pre-vote validation intentionally separates cheap identity binding
    from execution-derived checks.  Snapshot checkpoints and persisted canonical
    history do not get that replay step, so their stored body must be self-bound:
    transaction bodies, receipt bodies, helper-execution metadata, duplicated top-
    level header fields, block ID, and block hash must all agree with the canonical
    header commitments.
    """

    ok, reason, binding = validate_received_block_commitments(
        block=block,
        chain_id=chain_id,
    )
    if not ok or binding is None:
        return ok, reason, binding

    header = block.get("header")
    if not isinstance(header, dict):
        return False, "missing_header", None

    receipts = block.get("receipts")
    if not isinstance(receipts, list):
        return False, "receipts_missing", None
    canonical_receipts_root = compute_receipts_root(receipts=receipts)
    if canonical_receipts_root != str(header.get("receipts_root") or "").strip():
        return False, "receipts_root_mismatch", None

    helper_execution = block.get("helper_execution")
    header_helper_root = str(header.get("helper_execution_root") or "").strip()
    if helper_execution is not None and not isinstance(helper_execution, dict):
        return False, "helper_execution_invalid", None
    if isinstance(helper_execution, dict) and helper_execution:
        if not header_helper_root:
            return False, "unexpected_helper_execution", None
        computed_helper_root = compute_helper_execution_root(helper_execution=helper_execution)
        if computed_helper_root != header_helper_root:
            return False, "helper_execution_root_mismatch", None
    elif header_helper_root:
        return False, "helper_execution_missing", None

    # Canonical blocks duplicate a few header fields at top level for indexing and
    # transport ergonomics.  Durable history must not preserve contradictory aliases.
    for key in ("height", "block_ts_ms", "prev_block_hash"):
        if key not in block:
            continue
        if key in {"height", "block_ts_ms"}:
            try:
                if int(block.get(key)) != int(header.get(key)):
                    return False, f"top_level_{key}_mismatch", None
            except Exception:
                return False, f"top_level_{key}_mismatch", None
        elif str(block.get(key) or "").strip() != str(header.get(key) or "").strip():
            return False, f"top_level_{key}_mismatch", None

    top_chain_id = block.get("chain_id")
    if (
        top_chain_id is not None
        and str(top_chain_id or "").strip() != str(header.get("chain_id") or "").strip()
    ):
        return False, "top_level_chain_id_mismatch", None

    if binding.advertised_block_hash and binding.advertised_block_hash != binding.block_hash:
        return False, "block_hash_mismatch", None

    return True, "ok", binding


class BlockCommitmentBindingError(ValueError):
    """Raised when a received/persisted block is not canonically self-bound."""


def ensure_received_block_commitments(
    *,
    block: Json,
    chain_id: str,
) -> tuple[Json, ReceivedBlockCommitmentBinding]:
    """Recompute and enforce the complete received-block commitment tuple.

    This is the trust-boundary companion to ``validate_received_block_commitments``.
    It rejects body/header tx-id divergence, block-id aliases, and any advertised
    block hash that differs from the canonical header hash, then returns a copy
    rebound to the canonical identifiers.
    """

    ok, reason, binding = validate_received_block_commitments(
        block=block,
        chain_id=str(chain_id),
    )
    if not ok or binding is None:
        raise BlockCommitmentBindingError(str(reason or "block_commitment_invalid"))
    if binding.advertised_block_hash and binding.advertised_block_hash != binding.block_hash:
        raise BlockCommitmentBindingError("block_hash_mismatch")

    out = dict(block)
    out["block_id"] = binding.block_id
    out["block_hash"] = binding.block_hash
    return out, binding


def ensure_complete_block_commitments(
    *,
    block: Json,
    chain_id: str,
) -> tuple[Json, ReceivedBlockCommitmentBinding]:
    """Fail closed unless a durable/trusted block is completely self-bound."""

    ok, reason, binding = validate_complete_block_commitments(
        block=block,
        chain_id=str(chain_id),
    )
    if not ok or binding is None:
        raise BlockCommitmentBindingError(str(reason or "block_commitment_invalid"))
    out = dict(block)
    out["block_id"] = binding.block_id
    out["block_hash"] = binding.block_hash
    return out, binding


__all__ = [
    "BlockCommitmentBindingError",
    "ReceivedBlockCommitmentBinding",
    "ensure_complete_block_commitments",
    "ensure_received_block_commitments",
    "validate_complete_block_commitments",
    "validate_received_block_commitments",
]
