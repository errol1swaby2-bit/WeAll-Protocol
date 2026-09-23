#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PATH = Path(__file__).resolve().parent / "apply_r20_comprehensive_remediation.py"
ROOT = Path(__file__).resolve().parents[1]
STABLE_IDS_PATH = ROOT / "specs" / "v2" / "source" / "stable_ids.json"
EXPECTED_OLD = "c56accf266f627c128dc2a94574d2cdb17fc7029e1d16636cd034a7ea8d61bad"
EXPECTED_NEW = "da8b00a0ec85c56eae78bf28041ca9109df4be87b6b67479b9f973bd5e17562e"
R20_STATE_IDS = {
    "Content:account_id": "STATE-47E618BD7C1C1376",
    "Content:declared_by": "STATE-3C85D4A9A7E940B0",
    "Content:owner": "STATE-F2E8B1E3A0D4B350",
    "Economics:economics_lineage_v2_ready": "STATE-2C3E5397EDD6B9C5",
    "Groups:treasury_audit_anchors": "STATE-E12E9CCF4BCA3242",
    "Rewards:actual_forfeited": "STATE-F5F15A9DF6E37E88",
    "Roles:helper_reputation_required_milli": "STATE-F7E1B65C56D84E6E",
    "Roles:params": "STATE-39AD9EF90072894E",
    "Roles:suspended": "STATE-BBC0E78FB17523E3",
    "Storage:<pop:dynamic>": "STATE-D7B75274B7AE5DED",
    "Storage:confirmations": "STATE-4FDE62FE4D791CB4",
    "Storage:confirmed_target_count": "STATE-62B8291368648D29",
    "Storage:replication_factor": "STATE-6BC8D5FB6730EBB2",
    "Storage:targets": "STATE-1BF1149590175564",
}
R20_FAILURE_IDS = {
    "forbidden:appeal_actor_authority_unresolved": "FAIL-8A7CFE4E7D9903C2",
    "forbidden:appeal_actor_not_affected_party": "FAIL-E8C381EE45A91D42",
    "forbidden:content_target_owner_required": "FAIL-CE3C4B98063C93ED",
    "forbidden:deprecated_split_signer_authority_use_treasury_signers_set": "FAIL-2261B8189A0ACA51",
    "forbidden:economics_lineage_v2_not_proven": "FAIL-3924260089539A8F",
    "forbidden:forfeiture_exceeds_balance": "FAIL-41F00A8CA5B99AC5",
    "forbidden:helper_reputation_threshold_is_protocol_owned": "FAIL-58E062374D87F9F3",
}
OLD = '    insert_before_top_level_def(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'\n        def _declared_parent_tx_types(canon: TxIndex, tx_type: str) -> tuple[str, ...]:\n            info = _canon_info(canon, tx_type)\n            raw = info.get("parent_tx_types")\n            if isinstance(raw, list):\n                vals = tuple(str(x).strip().upper() for x in raw if str(x).strip())\n                if vals:\n                    return vals\n            one = str(info.get("parent_tx_type") or "").strip().upper()\n            return (one,) if one else ()\n\n        def _strict_receipt_lineage_required() -> bool:\n            return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() == "prod"\n        \'\'\',\n        finding="P2-CONS-006",\n    )\n    text = read("Weall-Protocol/src/weall/runtime/system_tx_engine.py")\n    if "\\nimport os\\n" not in text:\n        text = text.replace("from __future__ import annotations\\n", "from __future__ import annotations\\n\\nimport os\\n", 1)\n        write("Weall-Protocol/src/weall/runtime/system_tx_engine.py", text)\n    insert_at_function_start(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'\n        if _strict_receipt_lineage_required() and _is_receipt_only(canon, tx_type):\n            allowed_parents = _declared_parent_tx_types(canon, tx_type)\n            if allowed_parents:\n                raw_witness = payload.get("_lineage_witness")\n                if not isinstance(raw_witness, dict):\n                    return False, "lineage_witness_required"\n                witness_parent_type = str(raw_witness.get("parent_tx_type") or "").strip().upper()\n                if witness_parent_type not in allowed_parents:\n                    return False, "lineage_parent_tx_type_not_declared"\n                verdict0 = validate_lineage_witness(\n                    raw_witness,\n                    expected_child_tx_id=expected_queue_id,\n                    expected_child_tx_type=tx_type,\n                    expected_parent_tx_type=witness_parent_type,\n                )\n                if not verdict0.ok:\n                    return False, f"lineage_witness_invalid:{verdict0.reason}"\n        \'\'\',\n        finding="P2-CONS-006",\n    )'
NEW = '    insert_before_top_level_def(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'\n        def _declared_parent_tx_types(canon: TxIndex, tx_type: str) -> tuple[str, ...]:\n            info = _canon_info(canon, tx_type)\n            if not isinstance(info, dict):\n                return ()\n            raw = info.get("parent_tx_types")\n            if isinstance(raw, list):\n                vals = tuple(str(x).strip().upper() for x in raw if str(x).strip())\n                if vals:\n                    return vals\n            one = str(info.get("parent_tx_type") or "").strip().upper()\n            return (one,) if one else ()\n\n        def _strict_receipt_lineage_required(state: Json) -> bool:\n            params = state.get("params")\n            if not isinstance(params, dict):\n                return False\n            return bool(params.get("strict_civic_governance_enabled")) or bool(\n                params.get("validator_candidate_lifecycle_gate_enabled")\n            )\n        \'\'\',\n        finding="P2-CONS-006",\n    )\n    replace_once(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'    if found.tx_type != tx_type:\n        return False, "system_queue_tx_type_mismatch"\n    lineage_ok, lineage_reason, _ = _single_tx_lineage_shape(\n\'\'\',\n        \'\'\'    if found.tx_type != tx_type:\n        return False, "system_queue_tx_type_mismatch"\n    if _strict_receipt_lineage_required(state) and _is_receipt_only(canon, tx_type):\n        allowed_parents = _declared_parent_tx_types(canon, tx_type)\n        if allowed_parents:\n            raw_witness = payload.get("_lineage_witness")\n            if not isinstance(raw_witness, dict):\n                return False, "lineage_witness_required"\n            verdict0 = validate_lineage_witness(raw_witness)\n            if not verdict0.ok or verdict0.witness is None:\n                return False, f"lineage_witness_invalid:{verdict0.reason}"\n            witness0 = verdict0.witness\n            if witness0.parent_tx_type not in allowed_parents:\n                return False, "lineage_parent_tx_type_not_declared"\n            if witness0.kind is LineageWitnessKind.SINGLE_TX:\n                parent0 = _as_opt_str(getattr(env, "parent", None)).strip()\n                if not parent0 or witness0.parent_tx_id != parent0:\n                    return False, "lineage_parent_tx_id_mismatch"\n    lineage_ok, lineage_reason, _ = _single_tx_lineage_shape(\n\'\'\',\n        finding="P2-CONS-006",\n    )'
ALLOW_OLD = '    "Weall-Protocol/scripts/bootstrap_r20_remediation.py",\n'
ALLOW_NEW = (
    ALLOW_OLD
    + '    "Weall-Protocol/scripts/patch_r20_materialized_drivers.py",\n'
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def register_r20_state_ids() -> None:
    payload = json.loads(STABLE_IDS_PATH.read_text(encoding="utf-8"))
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("stable_ids.json entries must be a list")

    by_key = {
        (str(row.get("kind") or ""), str(row.get("canonical_key") or "")): row
        for row in entries
        if isinstance(row, dict)
    }
    by_id = {
        str(row.get("stable_id") or ""): row
        for row in entries
        if isinstance(row, dict) and str(row.get("stable_id") or "")
    }

    changed = False
    for canonical_key, stable_id in R20_STATE_IDS.items():
        expected_suffix = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16].upper()
        expected_id = f"STATE-{expected_suffix}"
        if stable_id != expected_id:
            raise SystemExit(
                f"r20 state stable-id derivation mismatch: {canonical_key}: "
                f"{stable_id} != {expected_id}"
            )

        existing = by_key.get(("state", canonical_key))
        if existing is not None:
            if str(existing.get("stable_id") or "") != stable_id:
                raise SystemExit(
                    f"r20 state key already registered to unexpected ID: "
                    f"{canonical_key}: {existing.get('stable_id')}"
                )
            print(f"stable ID already registered: {canonical_key} -> {stable_id}")
            continue

        collision = by_id.get(stable_id)
        if collision is not None:
            raise SystemExit(
                "r20 deterministic state ID collision: "
                f"{stable_id} already belongs to "
                f"{collision.get('kind')}:{collision.get('canonical_key')}"
            )

        row = {
            "aliases": [],
            "canonical_key": canonical_key,
            "kind": "state",
            "stable_id": stable_id,
            "status": "active",
        }
        entries.append(row)
        by_key[("state", canonical_key)] = row
        by_id[stable_id] = row
        changed = True
        print(f"registered stable ID: {canonical_key} -> {stable_id}")

    for canonical_key, stable_id in R20_FAILURE_IDS.items():
        expected_suffix = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16].upper()
        expected_id = f"FAIL-{expected_suffix}"
        if stable_id != expected_id:
            raise SystemExit(
                f"r20 failure stable-id derivation mismatch: {canonical_key}: "
                f"{stable_id} != {expected_id}"
            )

        existing = by_key.get(("failure", canonical_key))
        if existing is not None:
            if str(existing.get("stable_id") or "") != stable_id:
                raise SystemExit(
                    f"r20 failure key already registered to unexpected ID: "
                    f"{canonical_key}: {existing.get('stable_id')}"
                )
            print(f"stable ID already registered: {canonical_key} -> {stable_id}")
            continue

        collision = by_id.get(stable_id)
        if collision is not None:
            raise SystemExit(
                "r20 deterministic failure ID collision: "
                f"{stable_id} already belongs to "
                f"{collision.get('kind')}:{collision.get('canonical_key')}"
            )

        row = {
            "aliases": [],
            "canonical_key": canonical_key,
            "kind": "failure",
            "stable_id": stable_id,
            "status": "active",
        }
        entries.append(row)
        by_key[("failure", canonical_key)] = row
        by_id[stable_id] = row
        changed = True
        print(f"registered stable ID: {canonical_key} -> {stable_id}")

    if changed:
        STABLE_IDS_PATH.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )


def main() -> int:
    raw = PATH.read_bytes()
    actual = sha(raw)
    if actual != EXPECTED_OLD:
        raise SystemExit(f"phase-A materialized digest mismatch: {actual} != {EXPECTED_OLD}")
    text = raw.decode("utf-8")
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(f"phase-A lineage patch anchor mismatch: {count}")
    text = text.replace(OLD, NEW, 1)
    allow_count = text.count(ALLOW_OLD)
    if allow_count != 1:
        raise SystemExit(f"phase-A remediation allowlist anchor mismatch: {allow_count}")
    out = text.replace(ALLOW_OLD, ALLOW_NEW, 1).encode("utf-8")
    actual_new = sha(out)
    if actual_new != EXPECTED_NEW:
        raise SystemExit(f"phase-A corrected digest mismatch: {actual_new} != {EXPECTED_NEW}")
    PATH.write_bytes(out)
    register_r20_state_ids()
    print(f"corrected apply_r20_comprehensive_remediation.py sha256={actual_new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())