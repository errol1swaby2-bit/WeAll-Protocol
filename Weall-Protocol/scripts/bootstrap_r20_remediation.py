#!/usr/bin/env python3
from __future__ import annotations
import base64,gzip,hashlib,json
from pathlib import Path

PAYLOADS = {
    'apply_r20_comprehensive_remediation.py': ('r20_driver_a.py.gz.b64', 'c56accf266f627c128dc2a94574d2cdb17fc7029e1d16636cd034a7ea8d61bad'),
    'apply_r20_remaining_remediation.py': ('r20_driver_b.py.gz.b64', '8bfd5a19b854e0503ff59e9316a7ad068b7ac5843d337135c35f5e42095d40bd'),
}
CORRECTED_B_SHA256 = 'beef02e2ef6c1096050d58a64aa8a7bc29a6d4e5c02ab8731bcecf135522246d'
EXTRA_FAILURE_IDS = {
    'forbidden:pin_cid_mismatch': 'FAIL-EA9FB9C08DFE7F23',
    'forbidden:storage_offer_operator_must_match_signer': 'FAIL-2A1CB3AF55A41A07',
    'invalid_payload:missing_pin_or_operator': 'FAIL-3B49DB21C4ED0B7C',
    'invalid_payload:self_transfer_forbidden': 'FAIL-5B5956453E3B2F2E',
    'invalid_tx:missing_key_id': 'FAIL-B57D98F1582AA8F4',
    'invalid_tx:session_ttl_s_must_be_positive': 'FAIL-D40A4DAB3F037D44',
    'not_found:pin_not_found': 'FAIL-8DC2F2AAA82257FB',
}
R20_TRANSIENT_GENERATED = {
    'generated/r20_remaining_remediation_result.json': 'workflow-local remediation result uploaded as CI artifact; not a normative v2 source or declared release evidence',
    'generated/r20_remediation_driver_result.json': 'workflow-local remediation result uploaded as CI artifact; not a normative v2 source or declared release evidence',
    'generated/r20_repository_description_action.txt': 'workflow-local repository-description action note; not a normative v2 source or declared release evidence',
    'generated/r20_semantic_review_rebind.json': 'workflow-local semantic-review rebind diagnostic uploaded as CI artifact; not a normative v2 source or declared release evidence',
    'generated/r20_stale_semantic_reviews.json': 'workflow-local semantic-review diagnostic uploaded as CI artifact; not a normative v2 source or declared release evidence',
}
R20_TOOLING_MAPPINGS = {
    'scripts/bootstrap_r20_remediation.py',
    'scripts/patch_r20_materialized_drivers.py',
}

_HELPER = '''

def replace_once_in_def(rel: str, name: str, old: str, new: str, fid: str) -> None:
    text = base.read(rel)
    tree = ast.parse(text)
    matches = base._matching_defs(tree, name)
    if len(matches) != 1:
        raise RuntimeError(f"{fid}: expected exactly one function {name}, found {len(matches)}")
    start, end, _indent = base._node_span(text, matches[0])
    lines = text.splitlines(keepends=True)
    block = "".join(lines[start - 1 : end])
    count = block.count(old)
    if count != 1:
        raise RuntimeError(f"{fid}: {name} expected 1 scoped match, found {count}")
    lines[start - 1 : end] = [block.replace(old, new, 1)]
    out = "".join(lines)
    ast.parse(out, filename=rel)
    base.write(rel, out)
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

def _register_extra_failure_ids(here: Path) -> None:
    path = here.parent / 'specs' / 'v2' / 'source' / 'stable_ids.json'
    payload = json.loads(path.read_text(encoding='utf-8'))
    entries = payload.get('entries')
    if not isinstance(entries, list):
        raise SystemExit('stable_ids.json entries must be a list')
    by_key = {
        (str(row.get('kind') or ''), str(row.get('canonical_key') or '')): row
        for row in entries
        if isinstance(row, dict)
    }
    by_id = {
        str(row.get('stable_id') or ''): row
        for row in entries
        if isinstance(row, dict) and str(row.get('stable_id') or '')
    }
    changed = False
    for canonical_key, stable_id in EXTRA_FAILURE_IDS.items():
        expected = 'FAIL-' + hashlib.sha256(canonical_key.encode('utf-8')).hexdigest()[:16].upper()
        if stable_id != expected:
            raise SystemExit(f'extra failure stable-id derivation mismatch: {canonical_key}: {stable_id} != {expected}')
        existing = by_key.get(('failure', canonical_key))
        if existing is not None:
            if str(existing.get('stable_id') or '') != stable_id:
                raise SystemExit(f'extra failure key already registered to unexpected ID: {canonical_key}: {existing.get("stable_id")}')
            continue
        collision = by_id.get(stable_id)
        if collision is not None:
            raise SystemExit(f'extra failure ID collision: {stable_id} already belongs to {collision.get("kind")}:{collision.get("canonical_key")}')
        row = {
            'aliases': [],
            'canonical_key': canonical_key,
            'kind': 'failure',
            'stable_id': stable_id,
            'status': 'active',
        }
        entries.append(row)
        by_key[('failure', canonical_key)] = row
        by_id[stable_id] = row
        changed = True
        print(f'registered extra stable ID: {canonical_key} -> {stable_id}')
    if changed:
        path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')

def _register_r20_source_coverage(here: Path) -> None:
    path = here.parent / 'specs' / 'v2' / 'source' / 'source_mappings.json'
    payload = json.loads(path.read_text(encoding='utf-8'))
    excluded = payload.get('excluded_local_artifacts')
    mappings = payload.get('mappings')
    if not isinstance(excluded, list) or not isinstance(mappings, list):
        raise SystemExit('source_mappings.json must contain list exclusions and mappings')

    excluded_by_path = {
        str(row.get('path') or ''): row
        for row in excluded
        if isinstance(row, dict) and str(row.get('path') or '')
    }
    mapping_by_path = {
        str(row.get('path') or ''): row
        for row in mappings
        if isinstance(row, dict) and str(row.get('path') or '')
    }
    changed = False

    for rel, reason in sorted(R20_TRANSIENT_GENERATED.items()):
        existing = excluded_by_path.get(rel)
        expected = {
            'classification': 'ignored_local_generated_r20_workflow_artifact',
            'path': rel,
            'reason': reason,
        }
        if existing is not None:
            if existing != expected:
                raise SystemExit(f'r20 generated exclusion drift for {rel}: {existing!r}')
            continue
        excluded.append(expected)
        excluded_by_path[rel] = expected
        changed = True
        print(f'registered exact generated exclusion: {rel}')

    for rel in sorted(R20_TOOLING_MAPPINGS):
        existing = mapping_by_path.get(rel)
        expected = {
            'affected_registers': ['mechanisms', 'evidence'],
            'classification': 'authoritative_or_launch_critical',
            'path': rel,
            'primary_mechanism_id': 'M-076',
            'review_status': 'mapped_current_snapshot',
        }
        if existing is not None:
            if existing != expected:
                raise SystemExit(f'r20 tooling source mapping drift for {rel}: {existing!r}')
            continue
        mappings.append(expected)
        mapping_by_path[rel] = expected
        changed = True
        print(f'registered exact tooling mapping: {rel} -> M-076')

    if changed:
        path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')

def _repair_sqlite_staticmethod(here: Path) -> None:
    path = here.parent / 'src' / 'weall' / 'runtime' / 'sqlite_db.py'
    text = path.read_text(encoding='utf-8')
    broken = '    def _sqlite_synchronous_pragma() -> str:\\n'
    correct = '    @staticmethod\\n    def _sqlite_synchronous_pragma() -> str:\\n'
    correct_count = text.count(correct)
    broken_count = text.count(broken)
    if correct_count == 1:
        print('sqlite synchronous pragma staticmethod contract already intact')
        return
    if correct_count != 0 or broken_count != 1:
        marker = '_sqlite_synchronous_pragma'
        lines = text.splitlines()
        matches = [i for i, line in enumerate(lines) if marker in line]
        print(
            'unexpected sqlite synchronous pragma shape: '
            f'correct={correct_count} broken={broken_count} matches={len(matches)}'
        )
        for i in matches:
            start = max(0, i - 8)
            end = min(len(lines), i + 13)
            print(f'--- sqlite diagnostic lines {start + 1}-{end} ---')
            for n in range(start, end):
                print(f'{n + 1:04d}: {lines[n]}')
        raise SystemExit('sqlite synchronous pragma shape diagnostic captured; refusing to patch')
    repaired = text.replace(broken, correct, 1)
    compile(repaired, str(path), 'exec')
    path.write_text(repaired, encoding='utf-8')
    print('restored SqliteDB._sqlite_synchronous_pragma staticmethod contract')

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
    _register_extra_failure_ids(here)
    _register_r20_source_coverage(here)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
