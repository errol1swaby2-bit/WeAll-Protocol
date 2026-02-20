# src/weall/ledger/roles_schema.py
from __future__ import annotations

from typing import Any, Dict, List, Tuple

Json = Dict[str, Any]


def _as_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return str(x) if x is not None else ""


def _uniq_str_list(xs: Any) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for it in _as_list(xs):
        s = _as_str(it).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def ensure_roles_schema(ledger: Json) -> Json:
    """
    Ensure ledger['roles'] exists and contains the canonical role roots.
    Non-destructive: does not delete unknown keys.
    """
    roles = ledger.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        ledger["roles"] = roles

    roles.setdefault("treasuries_by_id", {})
    roles.setdefault("groups_by_id", {})

    # Validators
    roles.setdefault("validators", {"active_set": []})

    # Jurors / Node Operators / Creators: keep canonical shapes so that
    # Genesis reward accounting and domain apply modules have stable roots.
    roles.setdefault("jurors", {"by_id": {}, "active_set": []})
    roles.setdefault("node_operators", {"by_id": {}, "active_set": []})
    roles.setdefault("creators", {"by_id": {}, "active_set": []})
    roles.setdefault("emissaries", {})
    roles.setdefault("gov_executor", {"current": "", "active": True})

    # Normalize validator active_set to list[str]
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {"active_set": []}
        roles["validators"] = validators
    validators["active_set"] = _uniq_str_list(validators.get("active_set"))

    # Normalize other active_set lists
    for key in ("jurors", "node_operators", "creators"):
        obj = roles.get(key)
        if not isinstance(obj, dict):
            obj = {"by_id": {}, "active_set": []}
            roles[key] = obj
        obj["active_set"] = _uniq_str_list(obj.get("active_set"))
        if not isinstance(obj.get("by_id"), dict):
            obj["by_id"] = {}

    return roles


def set_treasury_signers(
    ledger: Json, treasury_id: str, signers: List[str], *, threshold: int = 1
) -> None:
    roles = ensure_roles_schema(ledger)
    treasuries = roles["treasuries_by_id"]
    if not isinstance(treasuries, dict):
        treasuries = {}
        roles["treasuries_by_id"] = treasuries

    tid = _as_str(treasury_id).strip()
    if not tid:
        raise ValueError("treasury_id must be non-empty")

    obj = treasuries.get(tid)
    if not isinstance(obj, dict):
        obj = {}
        treasuries[tid] = obj

    obj["signers"] = _uniq_str_list(signers)
    obj["threshold"] = int(threshold) if int(threshold) > 0 else 1


def set_group_signers(
    ledger: Json, group_id: str, signers: List[str], *, threshold: int = 1
) -> None:
    roles = ensure_roles_schema(ledger)
    groups = roles["groups_by_id"]
    if not isinstance(groups, dict):
        groups = {}
        roles["groups_by_id"] = groups

    gid = _as_str(group_id).strip()
    if not gid:
        raise ValueError("group_id must be non-empty")

    obj = groups.get(gid)
    if not isinstance(obj, dict):
        obj = {}
        groups[gid] = obj

    obj["signers"] = _uniq_str_list(signers)
    obj["threshold"] = int(threshold) if int(threshold) > 0 else 1


def set_group_moderators(ledger: Json, group_id: str, moderators: List[str]) -> None:
    roles = ensure_roles_schema(ledger)
    groups = roles["groups_by_id"]
    if not isinstance(groups, dict):
        groups = {}
        roles["groups_by_id"] = groups

    gid = _as_str(group_id).strip()
    if not gid:
        raise ValueError("group_id must be non-empty")

    obj = groups.get(gid)
    if not isinstance(obj, dict):
        obj = {}
        groups[gid] = obj

    obj["moderators"] = _uniq_str_list(moderators)


def migrate_legacy_role_shapes(ledger: Json) -> Tuple[int, List[str]]:
    """
    Best-effort migration from any legacy locations into canonical roles schema.

    This does NOT delete legacy data. It only copies forward if canonical is missing.

    Returns: (num_changes, notes)
    """
    notes: List[str] = []
    changes = 0

    roles = ensure_roles_schema(ledger)

    # ---- Treasury legacy sources ----
    legacy_roles = _as_dict(ledger.get("roles"))
    legacy_treasuries = _as_dict(legacy_roles.get("treasuries"))
    legacy_treasury_signers = _as_dict(legacy_roles.get("treasury_signers"))
    legacy_treasuries_by_id = _as_dict(legacy_roles.get("treasuries_by_id"))

    canonical_treasuries = roles.get("treasuries_by_id")
    if not isinstance(canonical_treasuries, dict):
        canonical_treasuries = {}
        roles["treasuries_by_id"] = canonical_treasuries

    # Merge candidates into canonical if missing
    for src_name, src in [
        ("roles.treasuries", legacy_treasuries),
        ("roles.treasury_signers", legacy_treasury_signers),
        ("roles.treasuries_by_id", legacy_treasuries_by_id),
    ]:
        for tid, obj in src.items():
            tid_s = _as_str(tid).strip()
            if not tid_s:
                continue

            can_obj = canonical_treasuries.get(tid_s)
            if isinstance(can_obj, dict) and "signers" in can_obj:
                continue  # already canonical

            signers: List[str] = []
            threshold = 1

            if isinstance(obj, dict):
                signers = _uniq_str_list(obj.get("signers") or obj.get("signer_set"))
                threshold = int(obj.get("threshold", 1) or 1)
            else:
                # allow dict/list stored directly at treasury id
                signers = _uniq_str_list(obj)

            if signers:
                canonical_treasuries[tid_s] = {
                    "signers": signers,
                    "threshold": threshold if threshold > 0 else 1,
                }
                changes += 1
                notes.append(f"migrated treasury signers for {tid_s} from {src_name}")

    # ---- Group legacy sources ----
    legacy_groups_by_id = _as_dict(legacy_roles.get("groups_by_id"))
    legacy_groups = _as_dict(legacy_roles.get("groups"))
    legacy_group_signers = _as_dict(legacy_roles.get("group_signers"))
    legacy_group_mods = _as_dict(legacy_roles.get("group_moderators"))

    canonical_groups = roles.get("groups_by_id")
    if not isinstance(canonical_groups, dict):
        canonical_groups = {}
        roles["groups_by_id"] = canonical_groups

    def _ensure_group(gid: str) -> Dict[str, Any]:
        obj = canonical_groups.get(gid)
        if not isinstance(obj, dict):
            obj = {}
            canonical_groups[gid] = obj
        return obj

    # migrate signers
    for src_name, src in [
        ("roles.groups_by_id", legacy_groups_by_id),
        ("roles.groups", legacy_groups),
        ("roles.group_signers", legacy_group_signers),
    ]:
        for gid, obj in src.items():
            gid_s = _as_str(gid).strip()
            if not gid_s:
                continue
            gobj = _ensure_group(gid_s)
            if "signers" in gobj:
                if "threshold" not in gobj:
                    gobj["threshold"] = 1
                continue
            if isinstance(obj, dict):
                signers = _uniq_str_list(obj.get("signers"))
                threshold = int(obj.get("threshold", 1) or 1)
            else:
                signers = _uniq_str_list(obj)
                threshold = 1
            if signers:
                gobj["signers"] = signers
                gobj["threshold"] = threshold if threshold > 0 else 1
                changes += 1
                notes.append(f"migrated group signers for {gid_s} from {src_name}")

    # migrate moderators
    for src_name, src in [
        ("roles.groups_by_id", legacy_groups_by_id),
        ("roles.groups", legacy_groups),
        ("roles.group_moderators", legacy_group_mods),
    ]:
        for gid, obj in src.items():
            gid_s = _as_str(gid).strip()
            if not gid_s:
                continue
            gobj = _ensure_group(gid_s)
            if "moderators" in gobj:
                continue
            mods = _uniq_str_list(obj.get("moderators") if isinstance(obj, dict) else obj)
            if mods:
                gobj["moderators"] = mods
                changes += 1
                notes.append(f"migrated group moderators for {gid_s} from {src_name}")

    return changes, notes
