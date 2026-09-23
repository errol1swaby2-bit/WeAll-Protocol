#!/usr/bin/env python3
from __future__ import annotations
import base64,gzip,hashlib
from pathlib import Path

PAYLOADS = {
    'apply_r20_comprehensive_remediation.py': ('r20_driver_a.py.gz.b64', 'c56accf266f627c128dc2a94574d2cdb17fc7029e1d16636cd034a7ea8d61bad'),
    'apply_r20_remaining_remediation.py': ('r20_driver_b.py.gz.b64', '8bfd5a19b854e0503ff59e9316a7ad068b7ac5843d337135c35f5e42095d40bd'),
}

def main() -> int:
    here=Path(__file__).resolve().parent
    for name,(payload_file,expected) in PAYLOADS.items():
        encoded=(here/payload_file).read_text(encoding='ascii').strip()
        raw=gzip.decompress(base64.b64decode(encoded))
        actual=hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise SystemExit(f"payload digest mismatch for {name}: {actual} != {expected}")
        (here/name).write_bytes(raw)
        print(f"materialized {name} sha256={actual}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
