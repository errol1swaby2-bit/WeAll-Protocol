from __future__ import annotations

import os

# A07-F002 canonical protocol wire budget.
#
# This is the single production authority for peer-message sizing. The 4-byte
# TCP/TLS frame prefix is transport framing and is not counted inside this
# payload budget.
MAX_WIRE_MESSAGE_BYTES = 1_000_000
MAX_TRANSPORT_FRAME_BYTES = MAX_WIRE_MESSAGE_BYTES
WIRE_FRAME_PREFIX_BYTES = 4

# Reserve enough room for the BFT_PROPOSAL envelope, proposer/view metadata,
# and a justification QC. The final encoded proposal is still checked against
# MAX_WIRE_MESSAGE_BYTES immediately before peer or relay emission.
BFT_PROPOSAL_WRAPPER_RESERVE_BYTES = 128 * 1024
MAX_BFT_BLOCK_BYTES = MAX_WIRE_MESSAGE_BYTES - BFT_PROPOSAL_WRAPPER_RESERVE_BYTES

# State-sync chunk payload sizing is derived from the same wire budget. Base64
# expands raw bytes by ~4/3; this reserve leaves room for the response header
# and chunk-integrity metadata.
STATE_SYNC_CHUNK_WRAPPER_RESERVE_BYTES = 96 * 1024
MAX_STATE_SYNC_CHUNK_RAW_BYTES = (
    (MAX_WIRE_MESSAGE_BYTES - STATE_SYNC_CHUNK_WRAPPER_RESERVE_BYTES) * 3 // 4
)
MAX_STATE_SYNC_CHUNKS = 4096
MAX_STATE_SYNC_TRANSFER_BYTES = MAX_STATE_SYNC_CHUNK_RAW_BYTES * MAX_STATE_SYNC_CHUNKS


class WireSizeError(ValueError):
    pass


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def ensure_wire_payload_size(
    payload: bytes | bytearray, *, limit: int = MAX_WIRE_MESSAGE_BYTES
) -> int:
    size = len(payload)
    cap = int(limit)
    if cap <= 0 or size > cap:
        raise WireSizeError(f"wire_message_too_large:{size}>{cap}")
    return size


def bft_block_limit_from_env() -> int:
    """Resolve the votecheck block budget without permitting prod drift.

    Non-production tests may lower/disable the legacy limit to exercise fast
    rejection paths. Production may not override the protocol-pinned value.
    """
    raw = os.environ.get("WEALL_BFT_VOTECHECK_MAX_BLOCK_BYTES")
    if raw is None or not str(raw).strip():
        return int(MAX_BFT_BLOCK_BYTES)
    try:
        value = int(str(raw).strip())
    except Exception as exc:
        raise WireSizeError("invalid_bft_wire_limit") from exc
    if _mode() == "prod" and value != int(MAX_BFT_BLOCK_BYTES):
        raise WireSizeError(f"production_bft_wire_limit_mismatch:{value}!={MAX_BFT_BLOCK_BYTES}")
    if _mode() == "prod":
        return int(MAX_BFT_BLOCK_BYTES)
    if value <= 0:
        return 0
    return min(int(value), int(MAX_BFT_BLOCK_BYTES))
