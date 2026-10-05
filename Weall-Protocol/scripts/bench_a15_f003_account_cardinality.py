from __future__ import annotations

import argparse
import gc
import json
import time
from hashlib import sha256

ACCOUNT_PADDING = "tier0-structured-state-synthetic:" + ("x" * 96)


def _account() -> dict:
    return {
        "nonce": 1,
        "account_type": "human",
        "poh_tier": 0,
        "banned": False,
        "locked": False,
        "synthetic_shape_padding": ACCOUNT_PADDING,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accounts", type=int, required=True)
    count = max(0, int(parser.parse_args().accounts))
    started = time.perf_counter()
    state = {
        "height": 1,
        "accounts": {f"@synthetic-{i:07d}": _account() for i in range(count)},
    }
    build_s = time.perf_counter() - started
    started = time.perf_counter()
    encoded = json.dumps(state, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    serialize_s = time.perf_counter() - started
    started = time.perf_counter()
    digest = sha256(encoded).hexdigest()
    hash_s = time.perf_counter() - started
    del state
    gc.collect()
    started = time.perf_counter()
    parsed = json.loads(encoded)
    restart_s = time.perf_counter() - started
    observed = len(parsed.get("accounts") or {})
    if observed != count:
        raise SystemExit("synthetic_account_count_mismatch")
    print(
        json.dumps(
            {
                "schema": "weall.a15_f003.account_cardinality_benchmark.v1",
                "accounts": count,
                "encoded_bytes": len(encoded),
                "build_seconds": round(build_s, 6),
                "canonical_serialize_seconds": round(serialize_s, 6),
                "canonical_preimage_sha256_seconds": round(hash_s, 6),
                "restart_json_parse_seconds": round(restart_s, 6),
                "canonical_preimage_sha256": digest,
                "synthetic": True,
                "note": "Cardinality-scaling evidence using bounded synthetic Tier-0-shaped records; not a production throughput or exact full-record-size benchmark.",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
