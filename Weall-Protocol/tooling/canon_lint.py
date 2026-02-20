#!/usr/bin/env python3
"""
WeAll Protocol Tx Canon Linter (v1.22.x schema)

Strict, production-grade linter for:
- Repo hygiene (forbidden dirs must not exist at all)
- Tx canon schema integrity and uniqueness
- Gate safety rules (no 'any', no 'guardian', no 'group_admin')
- Origin/context invariants (SYSTEM must be block-only; missing gate only for SYSTEM+block)
- Basic field typing sanity

Assumptions:
- Run from repo root
- Canon file located at: specs/tx_canon/tx_canon.yaml
- Canon schema:
    version: ...
    law: ...
    source: ...
    notes: ...
    txs:
      - id: int
        name: str
        domain: str
        origin: "USER"|"SYSTEM"|"VALIDATOR"
        context: "mempool"|"block"
        gate: (optional) str
        receipt_only: bool
        parent: (optional) str
        system_only: (optional) bool
        via_gov_execute: (optional) bool
        min_reputation: (optional) int
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


REPO_ROOT = Path.cwd()
CANON_PATH = REPO_ROOT / "specs" / "tx_canon" / "tx_canon.yaml"

# Repo must not contain these at all (not even empty)
FORBIDDEN_DIRS = ("data", "dev", "legacy")

# Explicitly forbidden gates (production safety)
FORBIDDEN_GATES = {"any", "guardian", "group_admin"}

# Allowed enumerations
ALLOWED_ORIGINS = {"USER", "SYSTEM", "VALIDATOR"}
ALLOWED_CONTEXTS = {"mempool", "block"}

# Tagging requirement: canon must include at least one of these tx names
# (your schema uses CONTENT_LABEL_SET right now, which qualifies)
TAG_TX_NAME_ALLOWLIST = {
    "CONTENT_LABEL_SET",
    "CONTENT_TAG_ADD",
    "CONTENT_TAG_REMOVE",
    "CONTENT_TAGS_SET",
    "CONTENT_TAG_SET",
}


def fail(msg: str) -> None:
    print(f"\n❌ CANON VIOLATION: {msg}\n", file=sys.stderr)
    sys.exit(1)


def warn(msg: str) -> None:
    print(f"⚠️  {msg}", file=sys.stderr)


def _import_yaml():
    try:
        import yaml  # type: ignore
        return yaml
    except Exception as e:
        fail(
            "PyYAML is required to lint the canon.\n"
            f"Import error: {e}\n\n"
            "Install with one of:\n"
            "  python3 -m pip install pyyaml\n"
            "  sudo apt-get install -y python3-yaml"
        )


def check_forbidden_directories() -> None:
    for d in FORBIDDEN_DIRS:
        p = REPO_ROOT / d
        if p.exists():
            fail(
                f"Forbidden directory '{d}/' exists.\n"
                "Protocol repos MUST NOT contain runtime/dev/legacy trees.\n"
                f"Delete '{d}/' entirely."
            )


def load_canon() -> Dict[str, Any]:
    if not CANON_PATH.exists():
        fail(f"Tx canon not found at: {CANON_PATH}")

    yaml = _import_yaml()
    try:
        with CANON_PATH.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        fail(f"Failed to parse canon YAML: {e}")

    if not isinstance(data, dict):
        fail("Canon root must be a mapping (YAML object).")

    return data


def expect_key(root: Dict[str, Any], k: str) -> Any:
    if k not in root:
        fail(f"Tx canon missing top-level '{k}'")
    return root[k]


def is_nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""


def check_root_schema(root: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Required top-level keys in your current schema
    expect_key(root, "version")
    expect_key(root, "law")
    expect_key(root, "source")
    expect_key(root, "notes")

    txs = expect_key(root, "txs")
    if not isinstance(txs, list):
        fail("Top-level 'txs' must be a list of tx objects.")

    if len(txs) == 0:
        fail("'txs' list is empty — canon must define at least one tx.")

    # light sanity
    if not is_nonempty_str(root.get("version")):
        warn("Top-level 'version' is not a non-empty string.")
    if not is_nonempty_str(root.get("law")):
        warn("Top-level 'law' is not a non-empty string.")
    if not is_nonempty_str(root.get("source")):
        warn("Top-level 'source' is not a non-empty string.")
    if not isinstance(root.get("notes"), (str, list, dict)):
        warn("Top-level 'notes' has an unusual type (expected str/list/dict).")

    return txs


def check_uniqueness(txs: List[Dict[str, Any]]) -> None:
    seen_ids = {}
    seen_names = {}

    for i, tx in enumerate(txs):
        tx_id = tx.get("id")
        tx_name = tx.get("name")

        if tx_id in seen_ids:
            fail(
                f"Duplicate tx id '{tx_id}'.\n"
                f"Seen in tx '{seen_ids[tx_id]}' and '{tx_name}'."
            )
        seen_ids[tx_id] = tx_name

        if tx_name in seen_names:
            fail(
                f"Duplicate tx name '{tx_name}'.\n"
                f"Seen at index {seen_names[tx_name]} and {i}."
            )
        seen_names[tx_name] = i


def check_tx_fields_and_types(txs: List[Dict[str, Any]]) -> None:
    required = {"id", "name", "domain", "origin", "context", "receipt_only"}

    for idx, tx in enumerate(txs):
        if not isinstance(tx, dict):
            fail(f"txs[{idx}] must be an object (mapping).")

        missing = required - set(tx.keys())
        if missing:
            fail(f"Tx '{tx.get('name', f'index {idx}')}' missing required fields: {sorted(missing)}")

        # id
        if not isinstance(tx["id"], int):
            fail(f"Tx '{tx['name']}' has non-int id: {tx['id']}")

        # name/domain
        if not is_nonempty_str(tx["name"]):
            fail(f"txs[{idx}] has empty/invalid 'name'")
        if not is_nonempty_str(tx["domain"]):
            fail(f"Tx '{tx['name']}' has empty/invalid 'domain'")

        # origin/context
        if tx["origin"] not in ALLOWED_ORIGINS:
            fail(f"Tx '{tx['name']}' origin must be one of {sorted(ALLOWED_ORIGINS)}; found '{tx['origin']}'")
        if tx["context"] not in ALLOWED_CONTEXTS:
            fail(f"Tx '{tx['name']}' context must be one of {sorted(ALLOWED_CONTEXTS)}; found '{tx['context']}'")

        # receipt_only
        if not isinstance(tx["receipt_only"], bool):
            fail(f"Tx '{tx['name']}' receipt_only must be bool; found {type(tx['receipt_only']).__name__}")

        # optional bools
        for opt_b in ("system_only", "via_gov_execute"):
            if opt_b in tx and not isinstance(tx[opt_b], bool):
                fail(f"Tx '{tx['name']}' {opt_b} must be bool; found {type(tx[opt_b]).__name__}")

        # optional ints
        if "min_reputation" in tx and not isinstance(tx["min_reputation"], int):
            fail(f"Tx '{tx['name']}' min_reputation must be int; found {type(tx['min_reputation']).__name__}")

        # optional strings
        if "parent" in tx and not is_nonempty_str(tx["parent"]):
            fail(f"Tx '{tx['name']}' parent must be a non-empty string if present")


def check_gate_rules(txs: List[Dict[str, Any]]) -> None:
    """
    Rules:
    - gate may be absent ONLY for SYSTEM + block context
    - forbidden gates: any/guardian/group_admin
    """
    for tx in txs:
        gate = tx.get("gate", None)
        origin = tx["origin"]
        context = tx["context"]

        if gate is None:
            if not (origin == "SYSTEM" and context == "block"):
                fail(
                    f"Tx '{tx['name']}' is missing 'gate' but is not SYSTEM+block.\n"
                    f"origin={origin}, context={context}"
                )
            continue

        if not is_nonempty_str(gate):
            fail(f"Tx '{tx['name']}' has invalid/empty gate value.")

        g = gate.strip().lower()
        if g in FORBIDDEN_GATES:
            fail(
                f"Tx '{tx['name']}' uses forbidden gate '{gate}'.\n"
                f"Forbidden: {sorted(FORBIDDEN_GATES)}"
            )


def check_system_origin_rules(txs: List[Dict[str, Any]]) -> None:
    """
    Rules:
    - SYSTEM txs must be block-only (no mempool SYSTEM)
    """
    for tx in txs:
        if tx["origin"] == "SYSTEM" and tx["context"] != "block":
            fail(
                f"SYSTEM tx '{tx['name']}' must be block-only.\n"
                f"Found context='{tx['context']}'"
            )


def check_tagging_presence(txs: List[Dict[str, Any]]) -> None:
    """
    You said tagging is user-attached identifying tags at upload time.
    In the current canon, this may be implemented as CONTENT_LABEL_SET.
    Enforce that at least one tag/label tx exists.
    """
    names = {tx["name"] for tx in txs}
    if not (names & TAG_TX_NAME_ALLOWLIST):
        fail(
            "No tag/label tx present.\n"
            "Expected at least one of:\n"
            f"  {sorted(TAG_TX_NAME_ALLOWLIST)}\n"
            "If you renamed the tag tx, update TAG_TX_NAME_ALLOWLIST in tooling/canon_lint.py."
        )


def main() -> None:
    check_forbidden_directories()

    root = load_canon()
    txs = check_root_schema(root)

    # Now validate tx list
    check_tx_fields_and_types(txs)
    check_uniqueness(txs)

    # Safety rules
    check_gate_rules(txs)
    check_system_origin_rules(txs)
    check_tagging_presence(txs)

    print("✅ Canon lint passed. Repo is protocol-clean.")


if __name__ == "__main__":
    main()
