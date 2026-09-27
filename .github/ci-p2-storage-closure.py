from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"
BRANCH = "p2-storage-closure-20260927"
TEMP_WORKFLOW = ".github/workflows/ci-p2-storage-closure.yml"
TEMP_SCRIPT = ".github/ci-p2-storage-closure.py"


def run(*args: str, cwd: Path = PROTO, env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=merged, check=True)


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one exact replacement, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_between(path: Path, start: str, end: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    start_at = text.find(start)
    if start_at < 0:
        raise SystemExit(f"{path}: missing start marker {start!r}")
    end_at = text.find(end, start_at)
    if end_at < 0:
        raise SystemExit(f"{path}: missing end marker {end!r}")
    if text.find(start, start_at + 1) >= 0 and text.find(start, start_at + 1) < end_at:
        raise SystemExit(f"{path}: ambiguous start marker {start!r}")
    path.write_text(text[:start_at] + replacement + text[end_at:], encoding="utf-8")


def patch_schema() -> None:
    path = PROTO / "src/weall/runtime/tx_schema.py"
    replace_between(
        path,
        "class StorageLeaseCreatePayload(_StrictModel):\n",
        "class StorageLeaseRenewPayload(_StrictModel):\n",
        '''class StorageLeaseCreatePayload(_StrictModel):
    offer_id: str = Field(..., min_length=1)
    lease_id: str | None = Field(
        default=None,
        min_length=1,
    )
    duration_blocks: int | None = Field(
        default=None,
        ge=0,
    )
    # Canonical reservation quantity.  Runtime legacy aliases remain replay-only;
    # new admission must carry this field explicitly when reserving less than the
    # offer's full capacity.
    size_bytes: int | None = Field(
        default=None,
        ge=1,
    )


''',
    )
    replace_between(
        path,
        "class IpfsPinConfirmPayload(_OptionalCidPayload):\n",
        "# ============================================================\n# Treasury + Groups domains\n",
        '''class IpfsPinConfirmPayload(_OptionalCidPayload):
    pin_id: str = Field(
        ...,
        min_length=1,
    )
    cid: str | None = Field(
        default=None,
        min_length=1,
    )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
    )
    ok: bool | int | None = None
    release: bool | None = None
    status: str | None = Field(default=None, min_length=1)
    retrieval_ok: bool | int | None = None
    availability_ok: bool | int | None = None
    retrieval_probe_id: str | None = Field(default=None, min_length=1)
    retrieval_sha256: str | None = Field(default=None, min_length=1)
    proof_hash: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_optional_cid(self) -> IpfsPinConfirmPayload:
        self._validate_cid_value(self.cid, "cid")
        return self


''',
    )


def patch_storage_runtime() -> None:
    path = PROTO / "src/weall/runtime/apply/storage.py"
    marker = "# ---------------------------------------------------------------------------\n# Offers / Leases / Proofs / Challenges\n# ---------------------------------------------------------------------------\n"
    lifecycle = '''def _release_lease_capacity(state: Json, lease: Json, *, release_height: int) -> bool:
    """Release a lease reservation exactly once without touching unrelated used bytes."""

    if bool(lease.get("capacity_released")):
        return False
    operator_id = _as_str(lease.get("operator_id") or lease.get("operator") or "").strip()
    size_bytes = _as_int(lease.get("size_bytes"), 0)
    if operator_id and size_bytes > 0:
        _adjust_storage_accounting(state, operator_id, allocated_delta=-int(size_bytes))
    lease["capacity_released"] = True
    lease["capacity_released_at_height"] = int(release_height)
    return bool(operator_id and size_bytes > 0)


def process_storage_lease_lifecycle(state: Json, *, next_height: int) -> list[str]:
    """Expire finite leases at the canonical block boundary deterministically."""

    storage = _ensure_storage(state)
    leases = storage.get("leases")
    if not isinstance(leases, dict):
        return []
    expired: list[str] = []
    boundary = int(next_height)
    for lease_id in sorted(leases, key=str):
        rec = leases.get(lease_id)
        if not isinstance(rec, dict) or _as_str(rec.get("status")).strip() != "active":
            continue
        end_height = _as_int(rec.get("end_height"), 0)
        if end_height <= 0 or boundary < end_height:
            continue
        _release_lease_capacity(state, rec, release_height=end_height)
        rec["status"] = "expired"
        rec["expired_at_height"] = int(end_height)
        rec["lifecycle_processed_at_height"] = int(boundary)
        leases[lease_id] = rec
        expired.append(str(lease_id))
    return expired


''' + marker
    replace_once(path, marker, lifecycle)

    replace_between(
        path,
        "def _apply_storage_lease_create(state: Json, env: TxEnvelope) -> Json:\n",
        "def _apply_storage_lease_renew(state: Json, env: TxEnvelope) -> Json:\n",
        '''def _apply_storage_lease_create(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _mk_id("lease", env, _pick(payload, "lease_id", "id"))
    offer_id = _pick(payload, "offer_id")
    if not offer_id:
        raise StorageApplyError("invalid_payload", "missing_offer_id", {"lease_id": lease_id})

    offers = s["offers"]
    offer = offers.get(offer_id)
    if not isinstance(offer, dict) or offer.get("status") != "active":
        raise StorageApplyError("not_found", "offer_not_active", {"offer_id": offer_id})

    operator_id = _as_str(offer.get("operator_id") or offer.get("operator") or "").strip()
    if not operator_id:
        raise StorageApplyError(
            "invalid_state", "offer_missing_operator_id", {"offer_id": offer_id}
        )

    leases = s["leases"]
    if lease_id in leases:
        return {"applied": "STORAGE_LEASE_CREATE", "lease_id": lease_id, "deduped": True}

    dur = _as_int(payload.get("duration_blocks"), _as_int(payload.get("blocks"), 0))
    if dur <= 0:
        dur = 1

    size_bytes = _as_int(
        _pick(payload, "size_bytes", "bytes", "capacity_bytes") or offer.get("capacity_bytes"), 0
    )
    if size_bytes > 0 and _capacity_available_for_allocation(state, operator_id) < int(size_bytes):
        raise StorageApplyError(
            "forbidden",
            "lease_size_exceeds_available_proven_capacity",
            {"operator_id": operator_id, "size_bytes": int(size_bytes)},
        )

    start_h = _height(state)
    end_h = start_h + dur
    rec: Json = {
        "lease_id": lease_id,
        "offer_id": offer_id,
        "operator_id": operator_id,
        "operator": operator_id,
        "lessee": env.signer,
        "account_id": env.signer,
        "status": "active",
        "start_height": int(start_h),
        "end_height": int(end_h),
        "created_at_nonce": int(env.nonce),
        "payload": payload,
    }
    if size_bytes > 0:
        rec["size_bytes"] = int(size_bytes)
        rec["capacity_released"] = False
    leases[lease_id] = rec

    if size_bytes > 0:
        _adjust_storage_accounting(state, operator_id, allocated_delta=int(size_bytes))

    proofs = s["proofs"]
    if lease_id not in proofs:
        proofs[lease_id] = []

    return {"applied": "STORAGE_LEASE_CREATE", "lease_id": lease_id, "deduped": False}


''',
    )

    replace_between(
        path,
        "def _apply_storage_lease_renew(state: Json, env: TxEnvelope) -> Json:\n",
        "def _apply_storage_lease_revoke(state: Json, env: TxEnvelope) -> Json:\n",
        '''def _apply_storage_lease_renew(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _pick(payload, "lease_id", "id")
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    leases = s["leases"]
    rec = leases.get(lease_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})
    if rec.get("lessee") != env.signer:
        raise StorageApplyError("forbidden", "only_lessee_can_renew", {"lease_id": lease_id})
    if _as_str(rec.get("status")).strip() != "active":
        raise StorageApplyError("forbidden", "lease_not_active", {"lease_id": lease_id})

    old_end = _as_int(rec.get("end_height"), 0)
    if old_end > 0 and _height(state) >= old_end:
        raise StorageApplyError("forbidden", "lease_expired", {"lease_id": lease_id})

    add_blocks = _as_int(payload.get("add_blocks"), _as_int(payload.get("duration_blocks"), 0))
    if add_blocks <= 0:
        add_blocks = 1

    rec["end_height"] = int(old_end + add_blocks)
    rec["renewed_at_nonce"] = int(env.nonce)
    rec["renew_payload"] = payload
    leases[lease_id] = rec
    return {"applied": "STORAGE_LEASE_RENEW", "lease_id": lease_id, "deduped": False}


''',
    )

    replace_between(
        path,
        "def _apply_storage_lease_revoke(state: Json, env: TxEnvelope) -> Json:\n",
        "def _apply_storage_proof_submit(state: Json, env: TxEnvelope) -> Json:\n",
        '''def _apply_storage_lease_revoke(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _pick(payload, "lease_id", "id")
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    leases = s["leases"]
    rec = leases.get(lease_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    operator_id = _as_str(rec.get("operator_id") or rec.get("operator") or "").strip()
    if not bool(getattr(env, "system", False)) and operator_id != env.signer:
        raise StorageApplyError(
            "forbidden", "only_operator_account_can_revoke", {"lease_id": lease_id}
        )

    status = _as_str(rec.get("status")).strip()
    if status in {"revoked", "expired"}:
        return {
            "applied": "STORAGE_LEASE_REVOKE",
            "lease_id": lease_id,
            "deduped": True,
            "status": status,
        }

    _release_lease_capacity(state, rec, release_height=_height(state))
    rec["status"] = "revoked"
    rec["revoked_at_height"] = int(_height(state))
    rec["revoked_at_nonce"] = int(env.nonce)
    rec["revoke_payload"] = payload
    leases[lease_id] = rec
    return {"applied": "STORAGE_LEASE_REVOKE", "lease_id": lease_id, "deduped": False}


''',
    )

    replace_between(
        path,
        "def _apply_storage_proof_submit(state: Json, env: TxEnvelope) -> Json:\n",
        "def _apply_storage_challenge_issue(state: Json, env: TxEnvelope) -> Json:\n",
        '''def _apply_storage_proof_submit(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _pick(payload, "lease_id")
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    leases = s["leases"]
    rec = leases.get(lease_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    operator_id = _as_str(rec.get("operator_id") or rec.get("operator") or "").strip()
    if operator_id != env.signer:
        raise StorageApplyError(
            "forbidden", "only_operator_account_can_submit_proof", {"lease_id": lease_id}
        )
    if _as_str(rec.get("status")).strip() != "active":
        raise StorageApplyError("forbidden", "lease_not_active", {"lease_id": lease_id})
    end_height = _as_int(rec.get("end_height"), 0)
    if end_height > 0 and _height(state) >= end_height:
        raise StorageApplyError("forbidden", "lease_expired", {"lease_id": lease_id})

    proofs = s["proofs"]
    if lease_id not in proofs:
        proofs[lease_id] = []

    proofs[lease_id].append(
        {
            "lease_id": lease_id,
            "at_nonce": int(env.nonce),
            "at_height": int(_height(state)),
            "proof_cid": _pick(payload, "proof_cid", "cid") or None,
            "payload": payload,
        }
    )
    return {"applied": "STORAGE_PROOF_SUBMIT", "lease_id": lease_id, "deduped": False}


''',
    )

    replace_between(
        path,
        "def _apply_ipfs_pin_confirm(state: Json, env: TxEnvelope) -> Json:\n",
        "# ---------------------------------------------------------------------------\n# Dispatcher entrypoint\n",
        '''def _pin_target_ids(rec: Json, key: str) -> list[str]:
    raw = rec.get(key)
    if not isinstance(raw, list):
        return []
    return sorted({_as_str(item).strip() for item in raw if _as_str(item).strip()})


def _recompute_pin_confirmation_state(rec: Json) -> None:
    targets = _pin_target_ids(rec, "targets")
    target_set = set(targets)
    rf = max(1, _as_int(rec.get("replication_factor"), 1))
    confirmed = sorted(set(_pin_target_ids(rec, "confirmed_targets")) & target_set)
    retrieved = sorted(set(_pin_target_ids(rec, "retrieval_confirmed_targets")) & target_set)
    released = sorted(set(_pin_target_ids(rec, "released_targets")) & target_set)
    rec["confirmed_targets"] = confirmed
    rec["retrieval_confirmed_targets"] = retrieved
    rec["released_targets"] = released
    rec["confirmed_target_count"] = len(confirmed)
    rec["retrieval_confirmed_target_count"] = len(retrieved)

    if targets and len(released) == len(targets):
        rec["status"] = "released"
        rec["durability_status"] = "released"
        rec["availability_status"] = "released"
        return

    if len(targets) >= rf and len(confirmed) >= rf:
        rec["status"] = "confirmed"
    elif _as_str(rec.get("status")).strip() not in {"reassigned", "degraded", "confirm_failed"}:
        rec["status"] = "confirmation_pending"

    if len(targets) >= rf and len(retrieved) >= rf:
        rec["durability_status"] = "retrieval_confirmed"
        rec["availability_status"] = "available"
    elif _as_str(rec.get("durability_status")).strip() not in {
        "degraded_no_spare_target",
        "reassignment_pending_confirmation",
    }:
        rec["durability_status"] = "retrieval_pending"
        rec["availability_status"] = "pending"


def _apply_ipfs_pin_confirm(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    pin_id = _as_str(_pick(payload, "pin_id", "id") or "").strip()
    if not pin_id:
        raise StorageApplyError("invalid_payload", "missing_pin_id", {"tx_type": env.tx_type})

    pins = s["pins"]
    rec_any = pins.get(pin_id)
    if not isinstance(rec_any, dict):
        raise StorageApplyError("not_found", "pin_not_found", {"pin_id": pin_id})
    rec = rec_any

    stored_cid = _as_str(rec.get("cid") or "").strip()
    if not stored_cid:
        raise StorageApplyError("invalid_state", "pin_missing_cid", {"pin_id": pin_id})
    supplied_cid = _as_str(_pick(payload, "cid", "ipfs_cid", "content_cid") or "").strip()
    if supplied_cid and supplied_cid != stored_cid:
        raise StorageApplyError(
            "invalid_payload",
            "pin_cid_mismatch",
            {"pin_id": pin_id, "expected_cid": stored_cid, "supplied_cid": supplied_cid},
        )
    cid = stored_cid
    validated = validate_ipfs_cid(cid)
    if not validated.ok:
        raise StorageApplyError("invalid_state", validated.reason, {"cid": validated.cid})

    targets = _pin_target_ids(rec, "targets")
    operator_id = _as_str(_pick(payload, "operator_id", "operator") or "").strip()
    if not operator_id and len(targets) == 1:
        operator_id = targets[0]
    if not operator_id:
        raise StorageApplyError("invalid_payload", "missing_operator_id", {"pin_id": pin_id})
    if operator_id not in targets:
        raise StorageApplyError(
            "forbidden",
            "pin_confirm_operator_not_current_target",
            {"pin_id": pin_id, "operator_id": operator_id, "targets": targets},
        )

    ok = payload.get("ok")
    ok_bool = bool(ok) if isinstance(ok, (bool, int)) else False
    if "ok" not in payload:
        ok_bool = True

    release_requested = bool(payload.get("release")) or _as_str(payload.get("status")).lower() in (
        "released",
        "unpin",
        "unpinned",
    )
    reassignment: Json = {"reassigned": False}
    if release_requested:
        released = set(_pin_target_ids(rec, "released_targets"))
        released.add(operator_id)
        rec["released_targets"] = sorted(released)
        _release_pin_accounting(state, pin_id, operator_id, _as_int(rec.get("size_bytes"), 0))
        rec["released_at_nonce"] = int(env.nonce)
        rec["released_at_height"] = int(_height(state))
        _recompute_pin_confirmation_state(rec)
    elif ok_bool:
        confirmed = set(_pin_target_ids(rec, "confirmed_targets"))
        confirmed.add(operator_id)
        rec["confirmed_targets"] = sorted(confirmed)
        rec["confirmed_at_nonce"] = int(env.nonce)
        rec["confirmed_at_height"] = int(_height(state))

        size_bytes = _as_int(rec.get("size_bytes"), 0)
        if size_bytes > 0 and _pin_accounting_marker_set(
            state, _pin_operator_key(pin_id, operator_id, "used")
        ):
            _adjust_storage_accounting(state, operator_id, used_delta=int(size_bytes))

        retrieval_flag = payload.get("retrieval_ok")
        if retrieval_flag is None:
            retrieval_flag = payload.get("availability_ok")
        if bool(retrieval_flag):
            retrieved = set(_pin_target_ids(rec, "retrieval_confirmed_targets"))
            retrieved.add(operator_id)
            rec["retrieval_confirmed_targets"] = sorted(retrieved)
            proofs = rec.get("retrieval_proofs")
            if not isinstance(proofs, list):
                proofs = []
            proof: Json = {
                "operator_id": operator_id,
                "at_nonce": int(env.nonce),
                "at_height": int(_height(state)),
                "cid": cid,
                "status": "retrievable",
            }
            for key in ("retrieval_probe_id", "retrieval_sha256", "proof_hash"):
                value = _as_str(payload.get(key)).strip()
                if value:
                    proof[key] = value
            if not any(
                isinstance(item, dict)
                and _as_str(item.get("operator_id")).strip() == operator_id
                and _as_str(item.get("cid")).strip() == cid
                for item in proofs
            ):
                proofs.append(proof)
            rec["retrieval_proofs"] = proofs
        _recompute_pin_confirmation_state(rec)
    else:
        confirmed = set(_pin_target_ids(rec, "confirmed_targets"))
        retrieved = set(_pin_target_ids(rec, "retrieval_confirmed_targets"))
        confirmed.discard(operator_id)
        retrieved.discard(operator_id)
        rec["confirmed_targets"] = sorted(confirmed)
        rec["retrieval_confirmed_targets"] = sorted(retrieved)
        rec["status"] = "confirm_failed"
        rec["failed_at_nonce"] = int(env.nonce)
        rec["failed_at_height"] = int(_height(state))
        size_bytes = _as_int(rec.get("size_bytes"), 0)
        if size_bytes > 0:
            _release_pin_accounting(state, pin_id, operator_id, int(size_bytes))
        reassignment = _maybe_reassign_failed_pin_target(
            state,
            pin_id=pin_id,
            rec=rec,
            failed_operator_id=operator_id,
            nonce=int(env.nonce),
        )
        rec["latest_reassignment"] = reassignment
        _recompute_pin_confirmation_state(rec)

    rec["confirm_payload"] = payload
    pins[pin_id] = rec
    s["pin_confirms"].append(
        {
            "pin_id": pin_id,
            "cid": cid,
            "operator_id": operator_id,
            "ok": bool(ok_bool),
            "release": bool(release_requested),
            "at_nonce": int(env.nonce),
            "at_height": int(_height(state)),
            "payload": payload,
        }
    )

    return {
        "applied": "IPFS_PIN_CONFIRM",
        "pin_id": pin_id,
        "operator_id": operator_id,
        "ok": bool(ok_bool),
        "receipt": True,
        "confirmed_target_count": _as_int(rec.get("confirmed_target_count"), 0),
        "retrieval_confirmed_target_count": _as_int(
            rec.get("retrieval_confirmed_target_count"), 0
        ),
        "reassignment": reassignment,
    }


''',
    )


def patch_scheduler() -> None:
    path = PROTO / "src/weall/runtime/scheduler_pipeline.py"
    replace_once(
        path,
        "from weall.runtime.apply.dispute import repair_unassigned_dispute_panels\n",
        "from weall.runtime.apply.dispute import repair_unassigned_dispute_panels\nfrom weall.runtime.apply.storage import process_storage_lease_lifecycle\n",
    )
    replace_once(
        path,
        "    repair_unassigned_dispute_panels(state, next_height=next_height)\n",
        "    repair_unassigned_dispute_panels(state, next_height=next_height)\n    process_storage_lease_lifecycle(state, next_height=next_height)\n",
    )


def patch_rehearsal() -> None:
    path = PROTO / "scripts/rehearse_storage_operator_durability_v1_5.py"
    replace_once(
        path,
        'state: dict[str, Any] = {"height": 100, "accounts": {"SYSTEM": {}}, "storage": {}}',
        'state: dict[str, Any] = {\n        "height": 100,\n        "params": {"ipfs_replication_factor": 2},\n        "accounts": {"SYSTEM": {}},\n        "storage": {},\n    }',
    )
    replace_once(
        path,
        '{"pin_id": "pin-live", "cid": cid, "size_bytes": 128, "replication_factor": 2}',
        '{"pin_id": "pin-live", "cid": cid, "size_bytes": 128}',
    )
    old = '''    ok = apply_storage(
        state,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            6,
            {
                "pin_id": "pin-live",
                "cid": cid,
                "operator_id": replacement,
                "ok": True,
                "retrieval_ok": True,
                "retrieval_probe_id": "probe-1",
            },
            system=True,
            parent="storage",
        ),
    )
    rec = state["storage"]["pins"]["pin-live"]
'''
    new = '''    if not replacement:
        return {"ok": False, "batch": "538", "reason": "reassignment_missing"}
    current_targets = list(state["storage"]["pins"]["pin-live"].get("targets") or [])
    survivor = next(op for op in current_targets if op != replacement)
    first_ok = apply_storage(
        state,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            6,
            {
                "pin_id": "pin-live",
                "cid": cid,
                "operator_id": survivor,
                "ok": True,
                "retrieval_ok": True,
                "retrieval_probe_id": "probe-survivor",
            },
            system=True,
            parent="storage",
        ),
    )
    partial = state["storage"]["pins"]["pin-live"].get("durability_status")
    ok = apply_storage(
        state,
        _env(
            "IPFS_PIN_CONFIRM",
            "SYSTEM",
            7,
            {
                "pin_id": "pin-live",
                "cid": cid,
                "operator_id": replacement,
                "ok": True,
                "retrieval_ok": True,
                "retrieval_probe_id": "probe-replacement",
            },
            system=True,
            parent="storage",
        ),
    )
    rec = state["storage"]["pins"]["pin-live"]
'''
    replace_once(path, old, new)
    replace_once(
        path,
        '        and bool(ok.get("ok"))\n        and rec.get("durability_status") == "retrieval_confirmed",',
        '        and bool(first_ok.get("ok"))\n        and partial != "retrieval_confirmed"\n        and bool(ok.get("ok"))\n        and rec.get("durability_status") == "retrieval_confirmed"\n        and rec.get("retrieval_confirmed_target_count") == 2,',
    )
    replace_once(
        path,
        '        "replacement_operator": replacement,\n',
        '        "replacement_operator": replacement,\n        "surviving_operator": survivor,\n        "partial_durability_status": partial,\n',
    )


def write_tests() -> None:
    path = PROTO / "tests/test_p2_storage_closure.py"
    path.write_text(
        '''from __future__ import annotations

import pytest

from weall.runtime import scheduler_pipeline
from weall.runtime.apply.storage import StorageApplyError, apply_storage
from weall.runtime.runtime_context import SchedulerSet
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.tx_schema import validate_tx_envelope

CID_1 = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7xqz7i"
CID_2 = "bafkreibm6jgqve7pzq3p7uwz3r3owz3oob7xjlkvyq5m4jdokwfvlq45aq"


def _system(tx_type: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent="storage:p2",
        system=True,
    )


def _strict(tx_type: str, payload: dict) -> None:
    validate_tx_envelope(
        {
            "tx_type": tx_type,
            "signer": "@alice",
            "nonce": 1,
            "payload": payload,
            "sig": "sig",
            "parent": None,
            "system": False,
            "chain_id": "test",
        }
    )


def test_p2_stor004_lease_size_bytes_passes_strict_canonical_admission() -> None:
    _strict(
        "STORAGE_LEASE_CREATE",
        {
            "offer_id": "offer:p2",
            "lease_id": "lease:p2",
            "duration_blocks": 10,
            "size_bytes": 4096,
        },
    )


def test_p2_stor002_confirm_durability_fields_pass_strict_canonical_admission() -> None:
    validate_tx_envelope(
        {
            "tx_type": "IPFS_PIN_CONFIRM",
            "signer": "SYSTEM",
            "nonce": 2,
            "payload": {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-a",
                "ok": True,
                "retrieval_ok": True,
                "availability_ok": True,
                "retrieval_probe_id": "probe:p2",
                "retrieval_sha256": "sha256:p2",
                "proof_hash": "proof:p2",
            },
            "sig": "sig",
            "parent": "storage:p2",
            "system": True,
            "chain_id": "test",
        }
    )


def test_p2_stor002_pin_confirm_binds_existing_cid_and_distinct_current_targets() -> None:
    state = {
        "height": 10,
        "params": {"ipfs_replication_factor": 2},
        "storage": {
            "pins": {
                "pin:p2": {
                    "pin_id": "pin:p2",
                    "cid": CID_1,
                    "size_bytes": 0,
                    "targets": ["op-a", "op-b"],
                    "replication_factor": 2,
                    "status": "requested",
                }
            }
        },
    }

    with pytest.raises(StorageApplyError, match="pin_not_found"):
        apply_storage(state, _system("IPFS_PIN_CONFIRM", 1, {"pin_id": "missing", "operator_id": "op-a"}))

    with pytest.raises(StorageApplyError, match="pin_cid_mismatch"):
        apply_storage(
            state,
            _system(
                "IPFS_PIN_CONFIRM",
                2,
                {"pin_id": "pin:p2", "cid": CID_2, "operator_id": "op-a", "ok": True},
            ),
        )

    with pytest.raises(StorageApplyError, match="pin_confirm_operator_not_current_target"):
        apply_storage(
            state,
            _system(
                "IPFS_PIN_CONFIRM",
                3,
                {"pin_id": "pin:p2", "cid": CID_1, "operator_id": "op-c", "ok": True},
            ),
        )

    apply_storage(
        state,
        _system(
            "IPFS_PIN_CONFIRM",
            4,
            {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-a",
                "ok": True,
                "retrieval_ok": True,
            },
        ),
    )
    rec = state["storage"]["pins"]["pin:p2"]
    assert rec["confirmed_targets"] == ["op-a"]
    assert rec["retrieval_confirmed_targets"] == ["op-a"]
    assert rec["status"] != "confirmed"
    assert rec["durability_status"] != "retrieval_confirmed"

    # Repeating one target cannot satisfy RF=2.
    apply_storage(
        state,
        _system(
            "IPFS_PIN_CONFIRM",
            5,
            {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-a",
                "ok": True,
                "retrieval_ok": True,
            },
        ),
    )
    assert rec["confirmed_target_count"] == 1
    assert rec["retrieval_confirmed_target_count"] == 1

    apply_storage(
        state,
        _system(
            "IPFS_PIN_CONFIRM",
            6,
            {
                "pin_id": "pin:p2",
                "cid": CID_1,
                "operator_id": "op-b",
                "ok": True,
                "retrieval_ok": True,
            },
        ),
    )
    assert rec["confirmed_targets"] == ["op-a", "op-b"]
    assert rec["retrieval_confirmed_targets"] == ["op-a", "op-b"]
    assert rec["status"] == "confirmed"
    assert rec["durability_status"] == "retrieval_confirmed"
    assert rec["availability_status"] == "available"


def _noop(*_args: object, **_kwargs: object) -> None:
    return None


def _noop_schedulers() -> SchedulerSet:
    return SchedulerSet(
        schedule_account_recovery_system_txs=_noop,
        schedule_poh_async_system_txs=_noop,
        schedule_poh_tier2_system_txs=_noop,
        schedule_poh_live_system_txs=_noop,
        schedule_node_operator_system_txs=_noop,
        schedule_reputation_accrual_system_txs=_noop,
        tick_governance_lifecycle=_noop,
        tick_dispute_lifecycle=_noop,
        system_tx_emitter=lambda *_args, **_kwargs: [],
        prune_emitted_system_queue=_noop,
    )


def test_p2_stor003_core_scheduler_expires_lease_and_releases_only_reserved_capacity_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "height": 9,
        "storage": {
            "leases": {
                "lease:p2": {
                    "lease_id": "lease:p2",
                    "operator_id": "op-a",
                    "operator": "op-a",
                    "lessee": "@alice",
                    "status": "active",
                    "start_height": 5,
                    "end_height": 10,
                    "size_bytes": 600,
                    "capacity_released": False,
                }
            },
            "operators": {
                "op-a": {
                    "allocated_bytes": 600,
                    "allocated_capacity_bytes": 600,
                    "used_bytes": 777,
                }
            },
        },
        "roles": {
            "node_operators": {
                "by_id": {
                    "op-a": {
                        "responsibilities": {
                            "storage": {
                                "allocated_capacity_bytes": 600,
                                "used_capacity_bytes": 777,
                            }
                        }
                    }
                }
            }
        },
    }
    for name in (
        "process_tier2_lifecycle",
        "process_evidence_lifecycle",
        "repair_pending_content_escalations",
        "repair_unassigned_dispute_panels",
    ):
        monkeypatch.setattr(scheduler_pipeline, name, _noop)

    schedulers = _noop_schedulers()
    scheduler_pipeline.run_core_schedulers(state, next_height=9, scheduler_set=schedulers)
    assert state["storage"]["leases"]["lease:p2"]["status"] == "active"

    scheduler_pipeline.run_core_schedulers(state, next_height=10, scheduler_set=schedulers)
    lease = state["storage"]["leases"]["lease:p2"]
    storage = state["roles"]["node_operators"]["by_id"]["op-a"]["responsibilities"]["storage"]
    operator = state["storage"]["operators"]["op-a"]
    assert lease["status"] == "expired"
    assert lease["expired_at_height"] == 10
    assert lease["capacity_released"] is True
    assert storage["allocated_capacity_bytes"] == 0
    assert operator["allocated_bytes"] == 0
    assert storage["used_capacity_bytes"] == 777
    assert operator["used_bytes"] == 777

    scheduler_pipeline.run_core_schedulers(state, next_height=11, scheduler_set=schedulers)
    assert storage["allocated_capacity_bytes"] == 0
    assert storage["used_capacity_bytes"] == 777


def test_p2_stor003_expired_lease_rejects_renewal_and_storage_proof() -> None:
    state = {
        "height": 10,
        "storage": {
            "leases": {
                "lease:p2": {
                    "lease_id": "lease:p2",
                    "operator_id": "op-a",
                    "operator": "op-a",
                    "lessee": "@alice",
                    "status": "expired",
                    "end_height": 10,
                }
            },
            "proofs": {},
        },
    }
    with pytest.raises(StorageApplyError, match="lease_not_active"):
        apply_storage(
            state,
            TxEnvelope(
                tx_type="STORAGE_LEASE_RENEW",
                signer="@alice",
                nonce=1,
                payload={"lease_id": "lease:p2", "add_blocks": 5},
            ),
        )
    with pytest.raises(StorageApplyError, match="lease_not_active"):
        apply_storage(
            state,
            TxEnvelope(
                tx_type="STORAGE_PROOF_SUBMIT",
                signer="op-a",
                nonce=2,
                payload={"lease_id": "lease:p2"},
            ),
        )
''',
        encoding="utf-8",
    )


def main() -> None:
    run("git", "rm", TEMP_WORKFLOW, TEMP_SCRIPT, cwd=ROOT)
    patch_schema()
    patch_storage_runtime()
    patch_scheduler()
    patch_rehearsal()
    write_tests()

    changed = [
        "src/weall/runtime/tx_schema.py",
        "src/weall/runtime/apply/storage.py",
        "src/weall/runtime/scheduler_pipeline.py",
        "scripts/rehearse_storage_operator_durability_v1_5.py",
        "tests/test_p2_storage_closure.py",
    ]
    run("ruff", "format", *changed)
    run("ruff", "check", *changed)
    run(sys.executable, "-m", "tooling.canon_lint")

    run("pytest", "-q", "tests/test_p2_storage_closure.py")
    run(sys.executable, "scripts/rehearse_storage_operator_durability_v1_5.py", "--json")

    run(sys.executable, "scripts/compile_v2_spec.py", env={"PYTHONPATH": "src"})
    run(sys.executable, "scripts/compile_v2_spec.py", "--check", env={"PYTHONPATH": "src"})
    run(sys.executable, "scripts/check_generated.py")
    run(
        sys.executable,
        "scripts/check_v15_public_readiness_artifacts.py",
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    run(sys.executable, "scripts/check_public_claim_freshness.py")
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")

    run("pytest", "-q")
    run("git", "diff", "--check", cwd=ROOT)

    run("git", "config", "user.name", "github-actions[bot]", cwd=ROOT)
    run(
        "git",
        "config",
        "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
        cwd=ROOT,
    )
    run("git", "add", "-A", cwd=ROOT)
    run("git", "diff", "--cached", "--check", cwd=ROOT)
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if staged.returncode == 0:
        raise SystemExit("storage closure produced no staged changes")
    if staged.returncode != 1:
        raise SystemExit(f"git diff --cached --quiet failed: {staged.returncode}")
    run("git", "commit", "-m", "Close P2 storage invariants", cwd=ROOT)
    run("git", "push", "origin", f"HEAD:{BRANCH}", cwd=ROOT)


if __name__ == "__main__":
    main()
