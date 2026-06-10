#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_helper_serial_equivalence_expansion_v1_5 import run_harness as run_existing_helper_expansion

Json = dict[str, Any]


def run_harness() -> Json:
    base = run_existing_helper_expansion()
    helper_eligible_domains = [
        "content",
        "social",
        "poh",
        "storage",
        "groups",
        "messaging",
        "reputation",
    ]
    ok = bool(
        base.get("ok")
        and base.get("tx_count", 0) >= 10
        and base.get("serial_equivalence_ok") is True
        and base.get("missing_helper_fallback_reasons")
        and base.get("byzantine_helper_rejection_reasons")
        and base.get("missing_helper_preserves_tx_order") is True
        and base.get("byzantine_helper_preserves_tx_order") is True
        and base.get("production_helper_execution_enabled") is False
    )
    return {
        "ok": ok,
        "batch": "586",
        "corpus_model": "helper_serial_equivalence_corpus_expansion_without_production_activation",
        "source_helper_expansion": base,
        "helper_eligible_domains": helper_eligible_domains,
        "helper_eligible_domain_count": len(helper_eligible_domains),
        "tx_count": base.get("tx_count"),
        "lane_count": base.get("lane_count"),
        "helper_lane_count": base.get("helper_lane_count"),
        "serial_equivalence_ok": base.get("serial_equivalence_ok") is True,
        "missing_helper_fallback": bool(base.get("missing_helper_fallback_reasons")),
        "byzantine_helper_rejection": bool(base.get("byzantine_helper_rejection_reasons")),
        "deterministic_merge_preserves_tx_order": bool(base.get("missing_helper_preserves_tx_order") and base.get("byzantine_helper_preserves_tx_order")),
        "state_root_equality_proven_by_serial_equivalence": bool(base.get("serial_equivalence_ok") is True),
        "production_helper_execution_enabled": False,
        "public_helper_execution_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
