from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weall.runtime.helper_contracts import build_helper_contract_map

OUT = ROOT / "generated" / "helper_contract_map.json"


def main() -> int:
    contract_map = build_helper_contract_map(ROOT / "generated" / "tx_index.json")
    OUT.write_text(json.dumps(contract_map, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    print("summary:", json.dumps(contract_map["summary"], sort_keys=True))
    print("instance_summary:", json.dumps(contract_map["instance_summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
