#!/usr/bin/env python3
from __future__ import annotations

import patch_r20_materialized_drivers_base as base

base.R20_FAILURE_IDS.update(
    {
        "forbidden:pin_cid_mismatch": "FAIL-EA9FB9C08DFE7F23",
    }
)

if __name__ == "__main__":
    raise SystemExit(base.main())
