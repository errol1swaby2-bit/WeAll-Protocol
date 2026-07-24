from __future__ import annotations

"""Deterministic handling for responsibilities that require active Tier 2."""

from typing import Any

Json = dict[str, Any]
SAFE_WITHDRAWAL_BLOCKS = 4_320


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _matches_account(value: Any, account_id: str) -> bool:
    raw = _as_str(value)
    base = raw.removeprefix("@")
    target = _as_str(account_id).removeprefix("@")
    return bool(base and base == target)


def _mark_mapping_records(mapping: Json, *, account_id: str, height: int, path: str, out: list[Json]) -> None:
    for key, record_any in sorted(mapping.items(), key=lambda item: str(item[0])):
        record = record_any if isinstance(record_any, dict) else None
        if record is None:
            continue
        identity = record.get("account_id") or record.get("member_id") or record.get("juror_id") or record.get("node_id") or key
        if not _matches_account(identity, account_id):
            continue
        status = _as_str(record.get("status")).lower()
        if status in {"revoked", "retired", "withdrawn", "inactive", "expired"}:
            continue
        record["tier2_expired_height"] = int(height)
        record["replacement_required"] = True
        record["no_new_assignments"] = True
        record["safe_withdrawal_until_height"] = int(height) + SAFE_WITHDRAWAL_BLOCKS
        record["status_before_tier2_expiry"] = status or None
        record["status"] = "replacement_required"
        out.append({
            "account_id": account_id,
            "path": path,
            "record_id": str(key),
            "replacement_required_height": int(height),
            "safe_withdrawal_until_height": int(height) + SAFE_WITHDRAWAL_BLOCKS,
            "status": "replacement_required",
        })


def mark_tier2_responsibilities_for_replacement(state: Json, *, account_id: str, height: int) -> list[Json]:
    transitions_root = state.setdefault("tier2_responsibility_transitions", {})
    by_account = transitions_root.setdefault("by_account", {})
    existing = by_account.get(account_id)
    if isinstance(existing, dict) and int(existing.get("expiry_height") or -1) == int(height):
        return list(existing.get("responsibilities") or [])

    out: list[Json] = []
    roles = state.get("roles")
    if isinstance(roles, dict):
        for role_name, role_root_any in sorted(roles.items(), key=lambda item: str(item[0])):
            role_root = role_root_any if isinstance(role_root_any, dict) else None
            if role_root is None:
                continue
            for field in ("by_id", "members", "assignments", "active"):
                mapping = role_root.get(field)
                if isinstance(mapping, dict):
                    _mark_mapping_records(
                        mapping,
                        account_id=account_id,
                        height=height,
                        path=f"roles.{role_name}.{field}",
                        out=out,
                    )
            active_set = role_root.get("active_set")
            if isinstance(active_set, list) and any(_matches_account(value, account_id) for value in active_set):
                replacement = role_root.setdefault("replacement_required_set", [])
                if account_id not in replacement:
                    replacement.append(account_id)

    # Account-local responsibility declarations are also canonical and are used
    # by several newer role surfaces.
    accounts = state.get("accounts")
    account = accounts.get(account_id) if isinstance(accounts, dict) else None
    responsibilities = account.get("responsibilities") if isinstance(account, dict) else None
    if isinstance(responsibilities, dict):
        _mark_mapping_records(
            responsibilities,
            account_id=account_id,
            height=height,
            path=f"accounts.{account_id}.responsibilities",
            out=out,
        )

    by_account[account_id] = {
        "account_id": account_id,
        "expiry_height": int(height),
        "responsibilities": out,
        "status": "replacement_or_safe_withdrawal",
    }
    transitions_root.setdefault("receipts", []).append(
        {
            "receipt_type": "tier2_responsibility_replacement_required",
            "account_id": account_id,
            "height": int(height),
            "responsibility_count": len(out),
            "safe_withdrawal_until_height": int(height) + SAFE_WITHDRAWAL_BLOCKS,
        }
    )
    return out


def process_safe_withdrawals(state: Json, *, next_height: int) -> int:
    root = state.get("tier2_responsibility_transitions")
    by_account = root.get("by_account") if isinstance(root, dict) else None
    if not isinstance(by_account, dict):
        return 0
    changed = 0
    for account_id, item_any in sorted(by_account.items()):
        item = item_any if isinstance(item_any, dict) else None
        if item is None or _as_str(item.get("status")) != "replacement_or_safe_withdrawal":
            continue
        deadlines = [int(rec.get("safe_withdrawal_until_height") or 0) for rec in item.get("responsibilities", []) if isinstance(rec, dict)]
        deadline = max(deadlines, default=0)
        if deadline and int(next_height) > deadline:
            item["status"] = "safe_withdrawal_elapsed"
            item["withdrawal_elapsed_height"] = int(next_height)
            changed += 1
    return changed


__all__ = ["SAFE_WITHDRAWAL_BLOCKS", "mark_tier2_responsibilities_for_replacement", "process_safe_withdrawals"]
