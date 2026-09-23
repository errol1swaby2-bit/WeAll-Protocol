#!/usr/bin/env python3
from __future__ import annotations
import base64,gzip,hashlib
from pathlib import Path

PAYLOADS = {
    'apply_r20_comprehensive_remediation.py': ('r20_driver_a.py.gz.b64', 'c56accf266f627c128dc2a94574d2cdb17fc7029e1d16636cd034a7ea8d61bad'),
    'apply_r20_remaining_remediation.py': ('r20_driver_b.py.gz.b64', '8bfd5a19b854e0503ff59e9316a7ad068b7ac5843d337135c35f5e42095d40bd'),
}
CORRECTED_B_SHA256 = 'f6d96f36f337481379e435231fae0770e6851fdcb7e79cfc8f0963cf70a2ea6e'

_HELPER = '''

def replace_once_in_def(rel: str, name: str, old: str, new: str, fid: str) -> None:
    text = base.read(rel)
    tree = ast.parse(text)
    matches = base._matching_defs(tree, name)
    if len(matches) != 1:
        raise RuntimeError(f"{fid}: expected exactly one function {name}, found {len(matches)}")
    start, end, block = base._node_span(text, matches[0])
    count = block.count(old)
    if count != 1:
        raise RuntimeError(f"{fid}: {name} expected 1 scoped match, found {count}")
    block = block.replace(old, new, 1)
    base.write(rel, text[:start] + block + text[end:])
    mark(fid)
'''

_OLD_ROLE = '''    replace_once(
        "Weall-Protocol/src/weall/runtime/apply/roles.py",
        '    rec["active"] = False\\n    rec["status"] = "paused"\\n    rec["suspended_at_nonce"] = int(env.nonce)\\n',
        '    rec["active"] = False\\n    rec["suspended"] = True\\n    rec["status"] = "paused"\\n    rec["suspended_at_nonce"] = int(env.nonce)\\n',
        "P1-ROLE-001")'''

_NEW_ROLE = '''    replace_once_in_def(
        "Weall-Protocol/src/weall/runtime/apply/roles.py",
        "_apply_role_node_operator_suspend",
        '    rec["active"] = False\\n    rec["status"] = "paused"\\n    rec["suspended_at_nonce"] = int(env.nonce)\\n',
        '    rec["active"] = False\\n    rec["suspended"] = True\\n    rec["status"] = "paused"\\n    rec["suspended_at_nonce"] = int(env.nonce)\\n',
        "P1-ROLE-001")'''

def _correct_phase_b(raw: bytes) -> bytes:
    text = raw.decode('utf-8')
    anchor = '\n\ndef insert_start(rel: str, name: str, source: str, fid: str) -> None:'
    if text.count(anchor) != 1:
        raise SystemExit(f'phase-B helper anchor mismatch: {text.count(anchor)}')
    if text.count(_OLD_ROLE) != 1:
        raise SystemExit(f'phase-B role anchor mismatch: {text.count(_OLD_ROLE)}')
    text = text.replace(anchor, _HELPER + anchor, 1)
    text = text.replace(_OLD_ROLE, _NEW_ROLE, 1)
    corrected = text.encode('utf-8')
    actual = hashlib.sha256(corrected).hexdigest()
    if actual != CORRECTED_B_SHA256:
        raise SystemExit(f'corrected phase-B digest mismatch: {actual} != {CORRECTED_B_SHA256}')
    return corrected

def main() -> int:
    here=Path(__file__).resolve().parent
    for name,(payload_file,expected) in PAYLOADS.items():
        encoded=(here/payload_file).read_text(encoding='ascii').strip()
        raw=gzip.decompress(base64.b64decode(encoded))
        actual=hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise SystemExit(f"payload digest mismatch for {name}: {actual} != {expected}")
        if name == 'apply_r20_remaining_remediation.py':
            raw = _correct_phase_b(raw)
            actual = hashlib.sha256(raw).hexdigest()
        (here/name).write_bytes(raw)
        print(f"materialized {name} sha256={actual}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
