#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

PATH = Path(__file__).resolve().parent / "apply_r20_comprehensive_remediation.py"
EXPECTED_OLD = "c56accf266f627c128dc2a94574d2cdb17fc7029e1d16636cd034a7ea8d61bad"
EXPECTED_NEW = "da8b00a0ec85c56eae78bf28041ca9109df4be87b6b67479b9f973bd5e17562e"
OLD = '    insert_before_top_level_def(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'\n        def _declared_parent_tx_types(canon: TxIndex, tx_type: str) -> tuple[str, ...]:\n            info = _canon_info(canon, tx_type)\n            raw = info.get("parent_tx_types")\n            if isinstance(raw, list):\n                vals = tuple(str(x).strip().upper() for x in raw if str(x).strip())\n                if vals:\n                    return vals\n            one = str(info.get("parent_tx_type") or "").strip().upper()\n            return (one,) if one else ()\n\n        def _strict_receipt_lineage_required() -> bool:\n            return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() == "prod"\n        \'\'\',\n        finding="P2-CONS-006",\n    )\n    text = read("Weall-Protocol/src/weall/runtime/system_tx_engine.py")\n    if "\\nimport os\\n" not in text:\n        text = text.replace("from __future__ import annotations\\n", "from __future__ import annotations\\n\\nimport os\\n", 1)\n        write("Weall-Protocol/src/weall/runtime/system_tx_engine.py", text)\n    insert_at_function_start(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'\n        if _strict_receipt_lineage_required() and _is_receipt_only(canon, tx_type):\n            allowed_parents = _declared_parent_tx_types(canon, tx_type)\n            if allowed_parents:\n                raw_witness = payload.get("_lineage_witness")\n                if not isinstance(raw_witness, dict):\n                    return False, "lineage_witness_required"\n                witness_parent_type = str(raw_witness.get("parent_tx_type") or "").strip().upper()\n                if witness_parent_type not in allowed_parents:\n                    return False, "lineage_parent_tx_type_not_declared"\n                verdict0 = validate_lineage_witness(\n                    raw_witness,\n                    expected_child_tx_id=expected_queue_id,\n                    expected_child_tx_type=tx_type,\n                    expected_parent_tx_type=witness_parent_type,\n                )\n                if not verdict0.ok:\n                    return False, f"lineage_witness_invalid:{verdict0.reason}"\n        \'\'\',\n        finding="P2-CONS-006",\n    )'
NEW = '    insert_before_top_level_def(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        "validate_system_tx_queue_binding",\n        \'\'\'\n        def _declared_parent_tx_types(canon: TxIndex, tx_type: str) -> tuple[str, ...]:\n            info = _canon_info(canon, tx_type)\n            if not isinstance(info, dict):\n                return ()\n            raw = info.get("parent_tx_types")\n            if isinstance(raw, list):\n                vals = tuple(str(x).strip().upper() for x in raw if str(x).strip())\n                if vals:\n                    return vals\n            one = str(info.get("parent_tx_type") or "").strip().upper()\n            return (one,) if one else ()\n\n        def _strict_receipt_lineage_required(state: Json) -> bool:\n            params = state.get("params")\n            if not isinstance(params, dict):\n                return False\n            return bool(params.get("strict_civic_governance_enabled")) or bool(\n                params.get("validator_candidate_lifecycle_gate_enabled")\n            )\n        \'\'\',\n        finding="P2-CONS-006",\n    )\n    replace_once(\n        "Weall-Protocol/src/weall/runtime/system_tx_engine.py",\n        \'\'\'    if found.tx_type != tx_type:\n        return False, "system_queue_tx_type_mismatch"\n    lineage_ok, lineage_reason, _ = _single_tx_lineage_shape(\n\'\'\',\n        \'\'\'    if found.tx_type != tx_type:\n        return False, "system_queue_tx_type_mismatch"\n    if _strict_receipt_lineage_required(state) and _is_receipt_only(canon, tx_type):\n        allowed_parents = _declared_parent_tx_types(canon, tx_type)\n        if allowed_parents:\n            raw_witness = payload.get("_lineage_witness")\n            if not isinstance(raw_witness, dict):\n                return False, "lineage_witness_required"\n            verdict0 = validate_lineage_witness(raw_witness)\n            if not verdict0.ok or verdict0.witness is None:\n                return False, f"lineage_witness_invalid:{verdict0.reason}"\n            witness0 = verdict0.witness\n            if witness0.parent_tx_type not in allowed_parents:\n                return False, "lineage_parent_tx_type_not_declared"\n            if witness0.kind is LineageWitnessKind.SINGLE_TX:\n                parent0 = _as_opt_str(getattr(env, "parent", None)).strip()\n                if not parent0 or witness0.parent_tx_id != parent0:\n                    return False, "lineage_parent_tx_id_mismatch"\n    lineage_ok, lineage_reason, _ = _single_tx_lineage_shape(\n\'\'\',\n        finding="P2-CONS-006",\n    )'
ALLOW_OLD = '    "Weall-Protocol/scripts/bootstrap_r20_remediation.py",\n'
ALLOW_NEW = (
    ALLOW_OLD
    + '    "Weall-Protocol/scripts/patch_r20_materialized_drivers.py",\n'
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    print(f"corrected apply_r20_comprehensive_remediation.py sha256={actual_new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
