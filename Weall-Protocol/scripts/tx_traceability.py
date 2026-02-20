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

Any unexpected exception is treated as a hard failure.
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


def _mk_env(tx_type: str, signer: str = "alice", nonce: int = 1) -> Any:
    # TxEnvelope is imported lazily; this function returns the actual instance.
    raise RuntimeError("TxEnvelope not bound yet")


def _claims(
    domain_name: str,
    apply_fn: Callable[[Json, Any], Json | None],
    err_types: tuple[type[BaseException], ...],
    tx_type: str,
    env_factory: Callable[[str], Any],
) -> tuple[bool, str | None]:
    st = _dummy_state()
    env = env_factory(tx_type)
    try:
        res = apply_fn(st, env)
        if isinstance(res, dict) and res.get("applied"):
            return True, None
        return False, None
    except err_types as e:
        # Domain explicitly rejected / does not claim (or claims by raising its domain error)
        # We treat "domain error" as: the function *recognized* the tx_type but rejected payload/permissions.
        # So: if it raised its domain error class, it's "claimed".
        return True, f"{domain_name}:{type(e).__name__}"
    except Exception as e:  # noqa: BLE001
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
    from weall.runtime.tx_admission import TxEnvelope  # type: ignore
    from weall.runtime.apply.identity import IdentityApplyError, apply_identity  # type: ignore
    from weall.runtime.apply.poh import PohApplyError, apply_poh  # type: ignore
    from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute  # type: ignore
    from weall.runtime.apply.content import ContentApplyError, apply_content  # type: ignore
    from weall.runtime.apply.groups import GroupsApplyError, apply_groups  # type: ignore
    from weall.runtime.apply.governance import GovApplyError, apply_governance  # type: ignore
    from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury  # type: ignore
    from weall.runtime.apply.roles import RolesApplyError, apply_roles  # type: ignore
    from weall.runtime.apply.consensus import ConsensusApplyError, apply_consensus  # type: ignore
    from weall.runtime.apply.indexing import IndexingApplyError, apply_indexing  # type: ignore
    from weall.runtime.apply.networking import NetworkingApplyError, apply_networking  # type: ignore
    from weall.runtime.apply.reputation import ReputationApplyError, apply_reputation  # type: ignore
    from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards  # type: ignore
    from weall.runtime.apply.messaging import MessagingApplyError, apply_messaging  # type: ignore
    from weall.runtime.apply.notifications import NotificationApplyError, apply_notifications  # type: ignore
    from weall.runtime.apply.social import SocialApplyError, apply_social  # type: ignore
    from weall.runtime.apply.economics import EconomicsApplyError, apply_economics  # type: ignore
    from weall.runtime.apply.storage import StorageApplyError, apply_storage  # type: ignore

    def env_factory(tx_type: str) -> TxEnvelope:
        return TxEnvelope(tx_type=tx_type, signer="alice", nonce=1, payload={})

    dispatch: tuple[tuple[str, Callable[[Json, Any], Json | None], tuple[type[BaseException], ...]], ...] = (
        ("identity", apply_identity, (IdentityApplyError,)),
        ("poh", apply_poh, (PohApplyError,)),
        ("dispute", apply_dispute, (DisputeApplyError,)),
        ("content", apply_content, (ContentApplyError,)),
        ("groups", apply_groups, (GroupsApplyError,)),
        ("governance", apply_governance, (GovApplyError,)),
        ("treasury", apply_treasury, (TreasuryApplyError,)),
        ("roles", apply_roles, (RolesApplyError,)),
        ("consensus", apply_consensus, (ConsensusApplyError,)),
        ("indexing", apply_indexing, (IndexingApplyError,)),
        ("networking", apply_networking, (NetworkingApplyError,)),
        ("reputation", apply_reputation, (ReputationApplyError,)),
        ("rewards", apply_rewards, (RewardsApplyError,)),
        ("messaging", apply_messaging, (MessagingApplyError,)),
        ("notifications", apply_notifications, (NotificationApplyError,)),
        ("social", apply_social, (SocialApplyError,)),
        ("economics", apply_economics, (EconomicsApplyError,)),
        ("storage", apply_storage, (StorageApplyError,)),
    )

    names = _load_canon_names(canon_path)

    results: dict[str, Any] = {"canon": str(canon_path), "total": len(names), "by_tx": {}}
    overlaps: dict[str, list[str]] = {}
    missing: list[str] = []
    unexpected: list[str] = []

    for tx in names:
        owners: list[str] = []
        reasons: dict[str, str] = {}
        for domain_name, fn, err_types in dispatch:
            ok, why = _claims(domain_name, fn, err_types, tx, env_factory=env_factory)
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
