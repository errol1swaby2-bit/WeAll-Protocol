from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.runtime.block_commitment_validation import (
    validate_complete_block_commitments,
)
from weall.runtime.block_hash import (
    BlockHashBindingError,
    ensure_canonical_block_hash,
)
from weall.runtime.commitments import normalize_validator_ids, validator_set_hash
from weall.runtime.json_tools import canonical_json_str
from weall.runtime.state_hash import compute_state_root, consensus_state_root_view
from weall.runtime.system_tx_engine import (
    SystemQueueCorruptionError,
    validate_system_queue_recovery_state,
)

Json = dict[str, Any]


def _mode() -> str:
    # Runtime posture is explicit; production code never infers pytest state.
    # Tests set WEALL_MODE=test in their harness when non-production behavior is required.
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip() or str(default))
    except Exception as exc:
        if _mode() == "prod":
            raise StateSyncVerifyError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    raw = str(v).strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    if not raw:
        return bool(default)
    if _mode() == "prod":
        raise StateSyncVerifyError(f"invalid_boolean_env:{name}")
    return bool(default)


def _trusted_anchor_env(default: bool) -> bool:
    """Read either trusted-anchor env alias and fail closed on conflict."""

    names = ("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR")
    seen: dict[str, bool] = {}
    for name in names:
        raw = os.environ.get(name)
        if raw is None:
            continue
        seen[name] = str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}
    if not seen:
        return bool(default)
    vals = set(seen.values())
    if len(vals) > 1:
        raise StateSyncVerifyError("trusted_anchor_env_conflict")
    return bool(next(iter(vals)))


def _finalized_anchor_env(default: bool) -> bool:
    raw = os.environ.get("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR")
    if raw is None:
        return bool(default)
    parsed = str(raw).strip().lower()
    if parsed in {"1", "true", "yes", "y", "on"}:
        return True
    if parsed in {"0", "false", "no", "n", "off"}:
        return False
    if not parsed:
        return bool(default)
    if _mode() == "prod":
        raise StateSyncVerifyError("invalid_boolean_env:WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR")
    return bool(default)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canon_json(obj: Any) -> str:
    return canonical_json_str(obj)


def sha256_hex_of(obj: Any) -> str:
    h = hashlib.sha256()
    h.update(_canon_json(obj).encode("utf-8"))
    return h.hexdigest()


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v or "").strip()


def _is_test_only_minimal_snapshot_checkpoint(checkpoint: Json) -> bool:
    """Return True only for the historical lightweight transport test fixture.

    Real checkpoint blocks are complete consensus objects and must be rebound
    through ``validate_complete_block_commitments``.  A few transport-level tests
    intentionally model only the snapshot/checkpoint pinning relation using the
    exact ``{height, block_id, header:{height,state_root}}`` shape.  Preserve that
    fixture only in explicit ``WEALL_MODE=test``; never infer compatibility from a
    malformed full block.
    """

    if _mode() != "test":
        return False
    if set(checkpoint) - {"height", "block_id", "header"}:
        return False
    header = checkpoint.get("header")
    if not isinstance(header, dict):
        return False
    if set(header) - {"height", "state_root"}:
        return False
    return bool(_as_str(checkpoint.get("block_id")))


def _block_hash_for_sync_chain(block: Json) -> str:
    """Return the block hash used by prev_block_hash ancestry checks.

    Runtime blocks use two identifiers: block_id for proposal/execution
    identity, and block_hash as the canonical header hash threaded through
    prev_block_hash. Delta state-sync validation must compare a block's
    prev_block_hash with the previous block's block_hash when available, while
    still accepting legacy/minimal blocks that only carry block_id ancestry.
    """

    if not isinstance(block, dict):
        return ""
    header = block.get("header")
    if isinstance(header, dict) and header:
        try:
            _bound, canonical_hash = ensure_canonical_block_hash(dict(block))
            return str(canonical_hash or "").strip()
        except Exception:
            return ""
    existing = block.get("block_hash")
    if isinstance(existing, str) and existing.strip():
        return existing.strip()
    legacy = block.get("hash")
    if isinstance(legacy, str) and legacy.strip():
        return legacy.strip()
    return ""


def _block_id_for_sync_chain(block: Json) -> str:
    """Return the execution/proposal block identifier for parent-id links."""

    if not isinstance(block, dict):
        return ""
    for key in ("block_id", "id"):
        value = block.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def state_sync_snapshot_view(snapshot: Json) -> Json:
    """Return the canonical peer-transferable checkpoint state.

    State sync must transfer the same protocol-semantic projection committed by
    the application state root, not sender-local runtime metadata. The canonical
    tip hash is reattached because checkpoint installation binds the state to the
    separately transferred tip block even though ``tip_hash`` is intentionally
    excluded from the application state root.
    """

    if not isinstance(snapshot, dict):
        raise StateSyncVerifyError("snapshot_not_object")
    out = consensus_state_root_view(snapshot)
    tip_hash = _as_str(snapshot.get("tip_hash") or snapshot.get("block_hash") or "").strip()
    if tip_hash:
        out["tip_hash"] = tip_hash
    return out


def _validate_snapshot_validator_authority(snapshot: Json) -> None:
    """Validate production validator membership/key authority at recovery boundaries.

    Normal validator-set transitions already fail closed unless every active
    member has a lifecycle registry key and the consensus verification registry
    carries the same key.  Snapshot recovery must enforce that same invariant;
    otherwise a hash-valid checkpoint can import state no legal transition could
    have produced and leave BFT unable to verify honest validators.
    """

    params = snapshot.get("params") if isinstance(snapshot.get("params"), dict) else {}
    if params.get("validator_candidate_lifecycle_gate_enabled") is not True:
        return

    consensus = snapshot.get("consensus") if isinstance(snapshot.get("consensus"), dict) else {}
    if "validator_set" in consensus and not isinstance(consensus.get("validator_set"), dict):
        raise StateSyncVerifyError("snapshot_validator_authority_invalid:validator_set_not_object")
    validator_set = (
        consensus.get("validator_set") if isinstance(consensus.get("validator_set"), dict) else {}
    )
    if "epoch" in validator_set:
        raw_epoch = validator_set.get("epoch")
        if isinstance(raw_epoch, bool) or not isinstance(raw_epoch, int) or raw_epoch < 0:
            raise StateSyncVerifyError(
                "snapshot_validator_authority_invalid:validator_epoch_invalid"
            )
    if "active_set" not in validator_set:
        return
    active_raw = validator_set.get("active_set")
    if not isinstance(active_raw, list):
        raise StateSyncVerifyError("snapshot_validator_authority_invalid:active_set_not_list")

    active = normalize_validator_ids(active_raw)
    stored_set_hash = _as_str(validator_set.get("set_hash") or "")
    if stored_set_hash and stored_set_hash != validator_set_hash(active):
        raise StateSyncVerifyError("snapshot_validator_authority_invalid:set_hash_mismatch")

    validators_root = (
        snapshot.get("validators") if isinstance(snapshot.get("validators"), dict) else {}
    )
    lifecycle_registry = (
        validators_root.get("registry") if isinstance(validators_root.get("registry"), dict) else {}
    )
    consensus_validators = (
        consensus.get("validators") if isinstance(consensus.get("validators"), dict) else {}
    )
    consensus_registry = (
        consensus_validators.get("registry")
        if isinstance(consensus_validators.get("registry"), dict)
        else {}
    )

    for account in active:
        lifecycle_rec = lifecycle_registry.get(account)
        if not isinstance(lifecycle_rec, dict):
            raise StateSyncVerifyError(
                f"snapshot_validator_authority_invalid:member_not_registered:{account}"
            )
        canonical_pubkey = _as_str(lifecycle_rec.get("pubkey") or "")
        if not canonical_pubkey:
            raise StateSyncVerifyError(
                f"snapshot_validator_authority_invalid:missing_canonical_pubkey:{account}"
            )
        consensus_rec = consensus_registry.get(account)
        consensus_pubkey = (
            _as_str(consensus_rec.get("pubkey") or "") if isinstance(consensus_rec, dict) else ""
        )
        if not consensus_pubkey:
            raise StateSyncVerifyError(
                f"snapshot_validator_authority_invalid:missing_consensus_pubkey:{account}"
            )
        if consensus_pubkey != canonical_pubkey:
            raise StateSyncVerifyError(
                f"snapshot_validator_authority_invalid:pubkey_mismatch:{account}"
            )


def _validate_snapshot_semantics(snapshot: Json) -> None:
    try:
        canonical_json_str(snapshot)
    except (TypeError, ValueError) as exc:
        raise StateSyncVerifyError("snapshot_not_strict_json") from exc

    try:
        validate_system_queue_recovery_state(snapshot)
    except SystemQueueCorruptionError as exc:
        raise StateSyncVerifyError(f"snapshot_system_queue_invalid:{exc}") from exc
    _validate_snapshot_validator_authority(snapshot)


def build_snapshot_anchor(snapshot: Json) -> Json:
    if not isinstance(snapshot, dict):
        raise StateSyncVerifyError("snapshot_not_object")
    _validate_snapshot_semantics(snapshot)
    finalized = snapshot.get("finalized") if isinstance(snapshot.get("finalized"), dict) else {}
    transferable = state_sync_snapshot_view(snapshot)
    return {
        "height": _as_int(snapshot.get("height"), 0),
        "tip_hash": _as_str(
            snapshot.get("tip_hash") or snapshot.get("tip") or snapshot.get("block_hash") or ""
        ),
        "state_root": compute_state_root(snapshot),
        "finalized_height": _as_int(finalized.get("height"), 0),
        "finalized_block_id": _as_str(
            finalized.get("block_id") or snapshot.get("finalized_block_id") or ""
        ),
        "snapshot_hash": sha256_hex_of(transferable),
    }


class StateSyncVerifyError(RuntimeError):
    pass


@dataclass
class StateSyncService:
    chain_id: str
    schema_version: str
    tx_index_hash: str
    state_provider: Callable[[], Json]
    # Optional provider to fetch blocks by height for delta sync.
    # Signature: (height:int) -> block dict | None
    block_provider: Callable[[int], Json | None] | None = None
    enable_delta: bool = True

    # Hardening caps (tunable by env).
    max_delta_blocks: int = 250
    max_snapshot_bytes: int = 0  # 0 = unlimited
    max_delta_bytes: int = 0  # 0 = unlimited
    require_header_match: bool = True
    fallback_to_snapshot: bool = True
    require_trusted_anchor: bool = False
    enforce_finalized_anchor: bool = False
    bft_enabled: bool | None = None

    def __post_init__(self) -> None:
        self.max_delta_blocks = max(
            1, _env_int("WEALL_SYNC_MAX_DELTA_BLOCKS", int(self.max_delta_blocks or 250))
        )
        self.max_snapshot_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_SNAPSHOT_BYTES", int(self.max_snapshot_bytes or 0))
        )
        self.max_delta_bytes = max(
            0, _env_int("WEALL_SYNC_MAX_DELTA_BYTES", int(self.max_delta_bytes or 0))
        )
        self.require_header_match = _env_bool(
            "WEALL_SYNC_REQUIRE_HEADER_MATCH", bool(self.require_header_match)
        )
        self.fallback_to_snapshot = _env_bool(
            "WEALL_SYNC_FALLBACK_TO_SNAPSHOT", bool(self.fallback_to_snapshot)
        )
        self.require_trusted_anchor = _trusted_anchor_env(bool(self.require_trusted_anchor))
        default_finalized = bool(self.enforce_finalized_anchor)
        if not default_finalized:
            mode = str(os.environ.get("WEALL_MODE") or "").strip().lower()
            bft_enabled = (
                bool(self.bft_enabled)
                if self.bft_enabled is not None
                else _env_bool("WEALL_BFT_ENABLED", False)
            )
            default_finalized = bool(mode == "prod" and bft_enabled)
        self.enforce_finalized_anchor = _finalized_anchor_env(default_finalized)

    def _header_ok(self, req: StateSyncRequestMsg) -> str | None:
        if not self.require_header_match:
            return None
        try:
            h = req.header
        except Exception:
            return "bad_header"
        if str(getattr(h, "chain_id", "")) != str(self.chain_id):
            return "chain_mismatch"
        if str(getattr(h, "schema_version", "")) != str(self.schema_version):
            return "schema_mismatch"
        if str(getattr(h, "tx_index_hash", "")) != str(self.tx_index_hash):
            return "tx_index_mismatch"
        return None

    def _size_ok(self, obj: Any, limit_bytes: int) -> bool:
        if limit_bytes <= 0:
            return True
        try:
            s = _canon_json(obj).encode("utf-8")
            return len(s) <= int(limit_bytes)
        except Exception:
            return False

    def _trusted_anchor_from_selector(self, selector: Any) -> Json | None:
        if not isinstance(selector, dict):
            return None
        anchor = selector.get("trusted_anchor")
        if isinstance(anchor, dict):
            return dict(anchor)
        return None

    def _anchor_matches(self, local_anchor: Json, trusted_anchor: Json) -> bool:
        # Only compare fields the requester explicitly pinned.
        for key in (
            "height",
            "tip_hash",
            "state_root",
            "finalized_height",
            "finalized_block_id",
            "snapshot_hash",
        ):
            if key in trusted_anchor and trusted_anchor.get(key) not in (None, ""):
                if _as_str(local_anchor.get(key)) != _as_str(trusted_anchor.get(key)):
                    return False
        return True

    def _trusted_finalized_height(self, trusted_anchor: Json | None) -> int:
        if not isinstance(trusted_anchor, dict):
            return 0
        return _as_int(trusted_anchor.get("finalized_height"), 0)

    def _trusted_finalized_block_id(self, trusted_anchor: Json | None) -> str:
        if not isinstance(trusted_anchor, dict):
            return ""
        return _as_str(trusted_anchor.get("finalized_block_id") or "")

    def _local_finalized_height(self, local_anchor: Json | None) -> int:
        if not isinstance(local_anchor, dict):
            return 0
        return _as_int(local_anchor.get("finalized_height"), 0)

    def handle_request(self, req: StateSyncRequestMsg) -> StateSyncResponseMsg:
        corr_id = req.header.corr_id
        hdr = WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=self.chain_id,
            schema_version=self.schema_version,
            tx_index_hash=self.tx_index_hash,
            sent_ts_ms=_now_ms(),
            corr_id=corr_id,
        )

        reason = self._header_ok(req)
        if reason:
            return StateSyncResponseMsg(header=hdr, ok=False, reason=reason, height=0)

        st = self.state_provider()
        if not isinstance(st, dict):
            return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_state", height=0)

        tip_h = int(st.get("height", 0) or 0)
        local_anchor = build_snapshot_anchor(st)
        trusted_anchor = self._trusted_anchor_from_selector(req.selector)
        if trusted_anchor is None and self.require_trusted_anchor:
            return StateSyncResponseMsg(
                header=hdr, ok=False, reason="trusted_anchor_required", height=tip_h
            )
        if trusted_anchor is not None and not self._anchor_matches(local_anchor, trusted_anchor):
            return StateSyncResponseMsg(
                header=hdr, ok=False, reason="trusted_anchor_mismatch", height=tip_h
            )

        def _snapshot_checkpoint_blocks() -> tuple[Json, ...] | None:
            if tip_h <= 0:
                return ()
            # Transport-only/test services may expose snapshots without block
            # history. Such snapshots can still be hashed/inspected, but the
            # executor will refuse to install a nonzero snapshot unless a
            # checkpoint block is present. Production executor services always
            # provide block_provider.
            if self.block_provider is None:
                return ()
            checkpoint = self.block_provider(tip_h)
            if not isinstance(checkpoint, dict):
                return None
            return (dict(checkpoint),)

        def _reply_snapshot(reason: str | None) -> StateSyncResponseMsg:
            snap = state_sync_snapshot_view(st)
            if not self._size_ok(snap, self.max_snapshot_bytes):
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="snapshot_too_large", height=tip_h
                )
            checkpoint_blocks = _snapshot_checkpoint_blocks()
            if checkpoint_blocks is None:
                return StateSyncResponseMsg(
                    header=hdr,
                    ok=False,
                    reason="snapshot_checkpoint_unavailable",
                    height=tip_h,
                )
            snap_hash = sha256_hex_of(snap)
            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=reason,
                height=tip_h,
                snapshot=snap,
                blocks=checkpoint_blocks,
                snapshot_hash=snap_hash,
                snapshot_anchor=local_anchor,
            )

        if req.mode == "snapshot":
            return _reply_snapshot(None)

        if req.mode == "delta":
            if not self.enable_delta:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="delta_disabled", height=tip_h
                )

            if self.block_provider is None:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="delta_unavailable", height=tip_h
                )

            start = int(req.from_height or 0)
            if start < 0 or start > tip_h:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="bad_from_height", height=tip_h
                )
            raw_end = int(req.to_height) if req.to_height is not None else tip_h
            if raw_end < 0:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="bad_to_height", height=tip_h
                )
            if req.to_height is not None and raw_end < start:
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="bad_height_range", height=tip_h
                )
            end = min(raw_end, tip_h)

            trusted_finalized_height = self._trusted_finalized_height(trusted_anchor)
            if self.enforce_finalized_anchor:
                local_finalized_height = self._local_finalized_height(local_anchor)
                finalized_cap = local_finalized_height
                if trusted_finalized_height > 0:
                    finalized_cap = min(finalized_cap, trusted_finalized_height)
                if finalized_cap > 0:
                    if start >= finalized_cap and end > finalized_cap:
                        return StateSyncResponseMsg(
                            header=hdr,
                            ok=False,
                            reason="delta_range_exceeds_finalized_anchor",
                            height=tip_h,
                        )
                    end = min(end, finalized_cap)

            if end - start > int(self.max_delta_blocks):
                end = start + int(self.max_delta_blocks)

            blocks: list[Json] = []
            for h in range(start + 1, end + 1):
                blk = self.block_provider(h)
                if not isinstance(blk, dict):
                    if self.fallback_to_snapshot:
                        return _reply_snapshot("fallback_snapshot")
                    return StateSyncResponseMsg(
                        header=hdr, ok=False, reason="delta_missing_block", height=tip_h
                    )
                blocks.append(blk)

            if self.max_delta_bytes > 0 and not self._size_ok(blocks, self.max_delta_bytes):
                return StateSyncResponseMsg(
                    header=hdr, ok=False, reason="delta_too_large", height=tip_h
                )

            return StateSyncResponseMsg(
                header=hdr,
                ok=True,
                reason=None,
                height=tip_h,
                snapshot=None,
                blocks=tuple(blocks),
                snapshot_hash=None,
                snapshot_anchor=local_anchor,
            )

        return StateSyncResponseMsg(header=hdr, ok=False, reason="bad_mode", height=tip_h)

    def verify_response(
        self, resp: StateSyncResponseMsg, trusted_anchor: Json | None = None
    ) -> None:
        if not isinstance(resp, StateSyncResponseMsg):
            raise StateSyncVerifyError("bad_response_type")
        try:
            hdr = resp.header
        except Exception as e:
            raise StateSyncVerifyError("missing_header") from e
        if hdr.type != MsgType.STATE_SYNC_RESPONSE:
            raise StateSyncVerifyError("bad_response_header:type")
        if _as_str(hdr.chain_id) != _as_str(self.chain_id):
            raise StateSyncVerifyError("bad_response_header:chain_id")
        if _as_str(hdr.schema_version) != _as_str(self.schema_version):
            raise StateSyncVerifyError("bad_response_header:schema_version")
        if _as_str(hdr.tx_index_hash) != _as_str(self.tx_index_hash):
            raise StateSyncVerifyError("bad_response_header:tx_index_hash")
        if not resp.ok:
            return

        anchor = resp.snapshot_anchor
        trusted_finalized_height = self._trusted_finalized_height(trusted_anchor)
        trusted_finalized_block_id = self._trusted_finalized_block_id(trusted_anchor)

        if trusted_anchor is not None:
            if not isinstance(anchor, dict):
                raise StateSyncVerifyError("missing_snapshot_anchor")
            if not self._anchor_matches(anchor, trusted_anchor):
                raise StateSyncVerifyError("trusted_anchor_mismatch")
            if self.enforce_finalized_anchor:
                if (
                    trusted_finalized_height > 0
                    and _as_int(anchor.get("finalized_height"), 0) != trusted_finalized_height
                ):
                    raise StateSyncVerifyError("trusted_finalized_anchor_mismatch:height")
                if (
                    trusted_finalized_block_id
                    and _as_str(anchor.get("finalized_block_id") or "")
                    != trusted_finalized_block_id
                ):
                    raise StateSyncVerifyError("trusted_finalized_anchor_mismatch:block_id")

        if isinstance(anchor, dict):
            anchor_height = _as_int(anchor.get("height"), 0)
            if (
                anchor_height > 0
                and int(resp.height or 0) > 0
                and anchor_height != int(resp.height)
            ):
                raise StateSyncVerifyError("snapshot_anchor_mismatch:height")

        if resp.snapshot is not None:
            if not isinstance(resp.snapshot, dict):
                raise StateSyncVerifyError("snapshot_not_object")
            if "bft" in resp.snapshot:
                raise StateSyncVerifyError("snapshot_contains_node_local_bft")
            transferable = state_sync_snapshot_view(resp.snapshot)
            if resp.snapshot != transferable:
                raise StateSyncVerifyError("snapshot_contains_nontransferable_state")
            _validate_snapshot_semantics(resp.snapshot)
            expect_hash = sha256_hex_of(transferable)
            have_hash = resp.snapshot_hash or ""
            if not isinstance(have_hash, str) or not have_hash:
                raise StateSyncVerifyError("missing_snapshot_hash")
            if have_hash != expect_hash:
                raise StateSyncVerifyError("snapshot_hash_mismatch")

            if not isinstance(anchor, dict):
                raise StateSyncVerifyError("missing_snapshot_anchor")
            computed_anchor = build_snapshot_anchor(resp.snapshot)
            for key in (
                "height",
                "tip_hash",
                "state_root",
                "finalized_height",
                "finalized_block_id",
                "snapshot_hash",
            ):
                if _as_str(anchor.get(key)) != _as_str(computed_anchor.get(key)):
                    raise StateSyncVerifyError(f"snapshot_anchor_mismatch:{key}")
            if trusted_anchor is not None and not self._anchor_matches(
                computed_anchor, trusted_anchor
            ):
                raise StateSyncVerifyError("trusted_anchor_mismatch")

            snapshot_height = _as_int(resp.snapshot.get("height"), 0)
            if resp.blocks:
                if snapshot_height <= 0:
                    raise StateSyncVerifyError("genesis_snapshot_checkpoint_unexpected")
                if not isinstance(resp.blocks, (tuple, list)) or len(resp.blocks) != 1:
                    raise StateSyncVerifyError("snapshot_checkpoint_count_invalid")
                checkpoint = resp.blocks[0]
                if not isinstance(checkpoint, dict):
                    raise StateSyncVerifyError("snapshot_checkpoint_bad_shape")
                checkpoint_height = _as_int(checkpoint.get("height"), 0)
                if checkpoint_height != snapshot_height:
                    raise StateSyncVerifyError("snapshot_checkpoint_height_mismatch")
                ok_binding, binding_reason, checkpoint_binding = (
                    validate_complete_block_commitments(
                        block=checkpoint,
                        chain_id=self.chain_id,
                    )
                )
                if not ok_binding or checkpoint_binding is None:
                    if not _is_test_only_minimal_snapshot_checkpoint(checkpoint):
                        if binding_reason == "block_hash_mismatch":
                            raise StateSyncVerifyError("snapshot_checkpoint_hash_mismatch")
                        raise StateSyncVerifyError(
                            f"snapshot_checkpoint_commitment_invalid:{binding_reason}"
                        )
                    try:
                        _checkpoint_bound, checkpoint_hash = ensure_canonical_block_hash(checkpoint)
                    except BlockHashBindingError as exc:
                        raise StateSyncVerifyError("snapshot_checkpoint_hash_mismatch") from exc
                    checkpoint_id = _as_str(checkpoint.get("block_id"))
                else:
                    if (
                        checkpoint_binding.advertised_block_hash
                        and checkpoint_binding.advertised_block_hash
                        != checkpoint_binding.block_hash
                    ):
                        raise StateSyncVerifyError("snapshot_checkpoint_hash_mismatch")
                    checkpoint_hash = checkpoint_binding.block_hash
                    checkpoint_id = checkpoint_binding.block_id
                if checkpoint_hash != _as_str(computed_anchor.get("tip_hash")):
                    raise StateSyncVerifyError("snapshot_checkpoint_hash_mismatch")
                snapshot_tip = _as_str(resp.snapshot.get("tip") or "")
                if snapshot_tip and checkpoint_id != snapshot_tip:
                    raise StateSyncVerifyError("snapshot_checkpoint_block_id_mismatch")
                header2 = (
                    checkpoint.get("header") if isinstance(checkpoint.get("header"), dict) else {}
                )
                if _as_str(header2.get("state_root") or "") != _as_str(
                    computed_anchor.get("state_root")
                ):
                    raise StateSyncVerifyError("snapshot_checkpoint_state_root_mismatch")

        # Delta-chain ancestry/range rules apply only to delta responses. A
        # snapshot checkpoint is independently pinned above to the snapshot tip,
        # state root and trusted snapshot anchor; it may legitimately be newer
        # than the last finalized height carried inside that same snapshot.
        if resp.blocks and resp.snapshot is None:
            if not isinstance(resp.blocks, (tuple, list)):
                raise StateSyncVerifyError("blocks_not_sequence")
            last_h: int | None = None
            last_bid: str = ""
            last_parent_id: str = ""
            response_height = int(resp.height or 0)
            trusted_height = (
                _as_int(trusted_anchor.get("height"), 0) if trusted_anchor is not None else 0
            )
            for blk in resp.blocks:
                if not isinstance(blk, dict):
                    raise StateSyncVerifyError("block_not_object")
                bh = blk.get("height")
                if bh is None:
                    continue
                try:
                    bh_i = int(bh)
                except Exception as e:
                    raise StateSyncVerifyError("block_height_bad") from e
                if bh_i <= 0:
                    raise StateSyncVerifyError("block_height_bad")
                if last_h is not None and bh_i != last_h + 1:
                    raise StateSyncVerifyError("block_height_not_contiguous")

                # Bound checks intentionally run before ancestry checks so a
                # response that extends past the announced/trusted/finalized
                # height reports the safety-bound violation, not a secondary
                # parent-link mismatch from blocks that should never be accepted.
                if response_height > 0 and bh_i > response_height:
                    raise StateSyncVerifyError("block_height_exceeds_response_height")
                if trusted_height > 0 and bh_i > trusted_height:
                    raise StateSyncVerifyError("block_height_exceeds_trusted_anchor")
                if (
                    self.enforce_finalized_anchor
                    and trusted_finalized_height > 0
                    and bh_i > trusted_finalized_height
                ):
                    raise StateSyncVerifyError("block_height_exceeds_finalized_anchor")

                if last_h is not None:
                    prev_hash = _as_str(blk.get("prev_block_hash") or "")
                    parent_id = _as_str(
                        blk.get("parent_block_id") or blk.get("prev_block_id") or ""
                    )

                    if prev_hash:
                        if last_bid:
                            if prev_hash != last_bid:
                                raise StateSyncVerifyError("block_prev_hash_mismatch")
                        elif last_parent_id and prev_hash != last_parent_id:
                            # Legacy/minimal fixtures sometimes use prev_block_hash
                            # to thread block_id ancestry. Accept that only when
                            # no canonical block hash is available for the prior
                            # block.
                            raise StateSyncVerifyError("block_prev_hash_mismatch")

                    if parent_id and last_parent_id and parent_id != last_parent_id:
                        raise StateSyncVerifyError("block_prev_hash_mismatch")

                last_h = bh_i
                last_bid = _block_hash_for_sync_chain(blk)
                last_parent_id = _block_id_for_sync_chain(blk)
