from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.runtime.block_hash import compute_block_hash
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


__all__ = ["ReceivedBlockCommitmentBinding", "validate_received_block_commitments"]
