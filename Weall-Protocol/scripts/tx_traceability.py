#!/usr/bin/env python3
"""
Tx traceability audit.

Goal:
- Ensure every canon tx type is "claimed" by exactly one domain apply function
  (identity/poh/dispute/content/groups/governance/etc).

This script:
- loads specs/tx_canon/tx_canon.yaml
- probes each domain apply function with a dummy env
- records which domain claims which tx type
- reports missing claims + overlaps (multiple domains claiming same tx)

Apply contract (as implemented in this repo):
- Each domain apply_* returns a meta dict if it handles the tx_type; otherwise None.
- If it recognizes the tx_type but rejects permissions/payload, it should raise ApplyError
  (or a domain-specific *ApplyError class).
- Any unexpected exception is treated as a hard failure.

Exit code:
- 0 if no missing/overlaps/unexpected
- 1 otherwise
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CANON_PATH = REPO_ROOT / "specs" / "tx_canon" / "tx_canon.yaml"
OUT_JSON = REPO_ROOT / "generated" / "tx_traceability.json"
OUT_MD = REPO_ROOT / "generated" / "tx_traceability.md"

Json = dict[str, Any]


def _load_canon_names(canon_path: Path) -> list[str]:
    d = yaml.safe_load(canon_path.read_text(encoding="utf-8"))
    if not isinstance(d, dict):
        raise SystemExit(f"canon invalid: expected mapping root in {canon_path}")
    txs = d.get("txs")
    if not isinstance(txs, list):
        raise SystemExit(f"canon invalid: expected list at 'txs' in {canon_path}")
    names: list[str] = []
    for t in txs:
        if not isinstance(t, dict):
            raise SystemExit(f"canon invalid: tx entry is not mapping in {canon_path}")
        name = t.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SystemExit(f"canon invalid: tx name missing/invalid in {canon_path}")
        names.append(name.strip())
    return names


def _dummy_state() -> Json:
    # Minimal state roots used across domains
    return {
        "accounts": {},
        "roles": {},
        "poh": {"accounts": {}, "requests": {}, "challenges": {}},
        "groups": {},
        "content": {"posts": {}, "threads": {}},
        "gov": {"proposals": {}, "params": {}},
        "treasury": {"treasuries": {}},
        "reputation": {},
        "economics": {"enabled": False},
        "storage": {"pins": {}, "replicas": {}},
        "consensus": {},
        "indexing": {},
        "messaging": {},
        "notifications": {},
        "social": {},
        "networking": {},
    }


def _is_apply_error(exc: BaseException, apply_error_type: type[BaseException]) -> bool:
    # Treat both the shared ApplyError base type and any domain-specific *ApplyError
    # (e.g. ConsensusApplyError) as "claimed" signals.
    if isinstance(exc, apply_error_type):
        return True
    return exc.__class__.__name__.endswith("ApplyError")


def _claims(
    domain_name: str,
    apply_fn: Callable[[Json, Any], Json | None],
    tx_type: str,
    env_factory: Callable[[str], Any],
    apply_error_type: type[BaseException],
) -> tuple[bool, str | None]:
    st = _dummy_state()
    env = env_factory(tx_type)
    try:
        res = apply_fn(st, env)
        # Domain contract: meta dict if handled; None otherwise.
        if res is None:
            return False, None
        return True, None
    except Exception as e:  # noqa: BLE001
        if _is_apply_error(e, apply_error_type):
            return True, f"{domain_name}:{type(e).__name__}"
        return False, f"unexpected:{domain_name}:{type(e).__name__}:{e}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canon", default=str(CANON_PATH))
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args()

    canon_path = Path(args.canon).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()

    # Dev convenience: allow running without `pip install -e .`
    # by adding repo/src to sys.path before importing weall.*
    sys.path.insert(0, str(REPO_ROOT / "src"))

    # Lazy imports (after sys.path tweak) to satisfy ruff E402.
    from weall.runtime.apply.consensus import apply_consensus  # type: ignore
    from weall.runtime.apply.content import apply_content  # type: ignore
    from weall.runtime.apply.dispute import apply_dispute  # type: ignore
    from weall.runtime.apply.economics import apply_economics  # type: ignore
    from weall.runtime.apply.governance import apply_governance  # type: ignore
    from weall.runtime.apply.groups import apply_groups  # type: ignore
    from weall.runtime.apply.identity import apply_identity  # type: ignore
    from weall.runtime.apply.indexing import apply_indexing  # type: ignore
    from weall.runtime.apply.messaging import apply_messaging  # type: ignore
    from weall.runtime.apply.networking import apply_networking  # type: ignore
    from weall.runtime.apply.notifications import apply_notifications  # type: ignore
    from weall.runtime.apply.poh import apply_poh  # type: ignore
    from weall.runtime.apply.reputation import apply_reputation  # type: ignore
    from weall.runtime.apply.rewards import apply_rewards  # type: ignore
    from weall.runtime.apply.roles import apply_roles  # type: ignore
    from weall.runtime.apply.social import apply_social  # type: ignore
    from weall.runtime.apply.storage import apply_storage  # type: ignore
    from weall.runtime.apply.treasury import apply_treasury  # type: ignore
    from weall.runtime.errors import ApplyError  # type: ignore
    from weall.runtime.tx_admission import TxEnvelope  # type: ignore

    def env_factory(tx_type: str) -> TxEnvelope:
        return TxEnvelope(tx_type=tx_type, signer="alice", nonce=1, payload={})

    dispatch: tuple[tuple[str, Callable[[Json, Any], Json | None]], ...] = (
        ("identity", apply_identity),
        ("poh", apply_poh),
        ("dispute", apply_dispute),
        ("content", apply_content),
        ("groups", apply_groups),
        ("governance", apply_governance),
        ("treasury", apply_treasury),
        ("roles", apply_roles),
        ("consensus", apply_consensus),
        ("indexing", apply_indexing),
        ("networking", apply_networking),
        ("reputation", apply_reputation),
        ("rewards", apply_rewards),
        ("messaging", apply_messaging),
        ("notifications", apply_notifications),
        ("social", apply_social),
        ("economics", apply_economics),
        ("storage", apply_storage),
    )

    names = _load_canon_names(canon_path)

    results: dict[str, Any] = {"canon": str(canon_path), "total": len(names), "by_tx": {}}
    overlaps: dict[str, list[str]] = {}
    missing: list[str] = []
    unexpected: list[str] = []

    for tx in names:
        owners: list[str] = []
        reasons: dict[str, str] = {}
        for domain_name, fn in dispatch:
            ok, why = _claims(
                domain_name,
                fn,
                tx,
                env_factory=env_factory,
                apply_error_type=ApplyError,
            )
            if ok:
                owners.append(domain_name)
                if why:
                    reasons[domain_name] = why
            elif why and why.startswith("unexpected:"):
                unexpected.append(f"{tx}:{why}")

        results["by_tx"][tx] = {"owners": owners, "reasons": reasons}

        if len(owners) == 0:
            missing.append(tx)
        elif len(owners) > 1:
            overlaps[tx] = owners

    results["missing"] = missing
    results["overlaps"] = overlaps
    results["unexpected"] = unexpected

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines: list[str] = []
    lines.append("# Tx traceability")
    lines.append("")
    lines.append(f"- canon: `{canon_path}`")
    lines.append(f"- total: **{len(names)}**")
    lines.append(f"- missing: **{len(missing)}**")
    lines.append(f"- overlaps: **{len(overlaps)}**")
    lines.append(f"- unexpected: **{len(unexpected)}**")
    lines.append("")

    if missing:
        lines.append("## Missing")
        lines.extend([f"- `{t}`" for t in missing])
        lines.append("")

    if overlaps:
        lines.append("## Overlaps")
        for t, owners in sorted(overlaps.items()):
            lines.append(f"- `{t}`: {', '.join(f'`{o}`' for o in owners)}")
        lines.append("")

    if unexpected:
        lines.append("## Unexpected errors")
        lines.extend([f"- `{x}`" for x in unexpected])
        lines.append("")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines), encoding="utf-8")

    print(f"✅ wrote {out_json}")
    print(f"✅ wrote {out_md}")

    if missing or overlaps or unexpected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
