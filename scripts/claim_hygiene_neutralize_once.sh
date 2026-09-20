#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(pwd)"
BACKEND="$ROOT/Weall-Protocol"

rm -f .github/workflows/claim-hygiene-neutralize-once.yml
rm -f scripts/claim_hygiene_neutralize_once.sh

git mv Weall-Protocol/docs/reviewer/NLNET_CURRENT_STATE_UPDATE_2026_08.md \
       Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md
git mv Weall-Protocol/docs/audits/late_stage_nlnet_public_testnet_gap_inventory_v1_5.md \
       Weall-Protocol/docs/audits/late_stage_public_testnet_gap_inventory_v1_5.md

python - <<'PY'
from pathlib import Path
import re

renames = {
    'NLNET_CURRENT_STATE_UPDATE_2026_08.md': 'CURRENT_STATE_UPDATE_2026_08.md',
    'late_stage_nlnet_public_testnet_gap_inventory_v1_5.md': 'late_stage_public_testnet_gap_inventory_v1_5.md',
}

reference_targets = [
    Path('README.md'),
    Path('Weall-Protocol/README.md'),
    Path('Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md'),
    Path('Weall-Protocol/docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md'),
    Path('Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md'),
    Path('Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md'),
    Path('Weall-Protocol/docs/REVIEWER_EVIDENCE_INDEX.md'),
    Path('Weall-Protocol/docs/PUBLIC_BETA_BLOCKERS.md'),
    Path('Weall-Protocol/docs/legal/PUBLIC_CLAIMS_CHECKLIST.md'),
    Path('Weall-Protocol/docs/audits/controlled_testnet_go_gate_closure_v1_5.md'),
    Path('Weall-Protocol/docs/audits/late_stage_public_testnet_gap_inventory_v1_5.md'),
    Path('Weall-Protocol/docs/audits/public_beta_blocker_reframe_after_step3_step4_v1_5.md'),
]

for p in reference_targets:
    if not p.exists():
        continue
    text = p.read_text(encoding='utf-8')
    for old, new in renames.items():
        text = text.replace(old, new)
    p.write_text(text, encoding='utf-8')

Path('Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md').write_text('''# WeAll current state update

Status: pre-public-testnet / mainnet-readiness hardening.

This document summarizes current repository evidence. Generated artifacts remain authoritative for mutable readiness facts.

## Current claim boundary

WeAll is an open-source deterministic civic coordination protocol implementation under active hardening. The repository contains implementation-stage code, tests, generated artifacts, operator runbooks, public civic surfaces, governance, disputes, reputation, observer/testnet tooling, tokenomics scaffolding, and protocol-safety boundaries.

Current generated state keeps public beta and mainnet readiness unclaimed. Controlled-testnet mechanism completion is also currently **NO-GO** because the production-helper state-root/restart equivalence gate remains incomplete.

Do not infer public validator safety, public multi-validator BFT readiness, live economics, automatic software upgrades, production helper execution, legal/compliance approval, public storage-market readiness, or completed production cryptographic review from local repository evidence.

## Public-only protocol direction

Protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and protocol-state activity is intended to be publicly inspectable. Group membership may gate participation and administration, but it must not gate read visibility for protocol-native social or civic content. Sensitive Proof-of-Humanity evidence, account recovery secrets, private keys, and private local UI preferences remain outside that public-state rule.

## Current evidence posture

Repository evidence includes public-only regression checks, signed/pinned observer discovery inputs, governance/dispute lifecycle tests, record-only protocol-upgrade tests, economics-lock tests, release hygiene, secret guard, generated artifact checks, and deterministic source/derivative validation.

External evidence remains required for stronger launch claims, including independent validator/operator operation, cross-machine replay, real storage/IPFS operation, legal/compliance attestation, executable upgrade staging/rollback proof, production-helper topology proof, external observer journey evidence, and independent cryptographic review.

## Performance boundary

Historical local throughput measurements exist, but **no scalar TPS value is a current verified performance claim for this tree**. Any future scalar performance claim must be bound to the exact commit/tree and document workload semantics, cryptographic/signature behavior, persistence, network/consensus scope, topology, hardware, OS/runtime, warmup, duration, repetitions, latency and throughput distributions, error rate, and resource utilization.

## Canonical verification sources

Use the current generated artifacts rather than prose copies of mutable values:

- `generated/public_beta_blocker_report_v1_5.json`
- `generated/controlled_testnet_go_gate_v1_5.json`
- `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`
- `generated/release_evidence_manifest_v1_5.json`
- `generated/tx_index.json`
- `generated/v2/spec_compilation_manifest.json`
- `docs/CURRENT_VERIFIED_CLAIMS.md`

Current blocker totals, transaction counts, route counts, test counts, and other mutable measurements should be read directly from their generated authority instead of copied into this document.
''', encoding='utf-8')

replacements = [
    ('NLnet/public-testnet reviewer claim', 'public-testnet scope'),
    ('NLnet / public-testnet reviewer readiness hardening', 'public-testnet readiness hardening'),
    ('NLnet / reviewer current-state update', 'current-state update'),
    ('NLnet first-round review', 'the current release boundary'),
    ('NLnet first-round selection', 'the current release boundary'),
    ('before NLnet first-round', 'with current repository evidence'),
    ('NLnet', 'project'),
    ('grant-funded hardening', 'continued hardening'),
    ('grant update', 'project update'),
    ('funded mainnet-readiness hardening', 'mainnet-readiness hardening'),
    ('funded hardening path', 'hardening path'),
    ('Remaining funded work', 'Remaining work'),
    ('remaining funded work', 'remaining work'),
    ('reviewer-facing', 'verification-facing'),
    ('Reviewer-facing', 'Verification-facing'),
    ('reviewer-visible', 'verification-visible'),
    ('Reviewer-visible', 'Verification-visible'),
    ('reviewer confidence', 'verification confidence'),
    ('reviewer-confidence', 'verification-confidence'),
    ('Reviewer verification path', 'Verification path'),
    ('reviewer verification path', 'verification path'),
    ('Reviewer evidence', 'Verification evidence'),
    ('reviewer evidence', 'verification evidence'),
    ('Reviewer starting points', 'Verification starting points'),
    ('reviewer starting points', 'verification starting points'),
    ('Reviewer conclusion', 'Current evidence conclusion'),
    ('reviewer conclusion', 'current evidence conclusion'),
    ('reviewer setup path', 'verification setup path'),
    ('Reviewer setup path', 'Verification setup path'),
    ('current reviewer framing', 'current verification framing'),
    ('Current reviewer framing', 'Current verification framing'),
    ('reviewer-facing documentation', 'verification documentation'),
    ('reviewer docs', 'verification docs'),
    ('Reviewer docs', 'Verification docs'),
    ('reviewer runbooks', 'verification runbooks'),
    ('Reviewer runbooks', 'Verification runbooks'),
    ('reviewer flow', 'verification flow'),
    ('Reviewer flow', 'Verification flow'),
    ('reviewer wording', 'claim wording'),
    ('Reviewer wording', 'Claim wording'),
]

presentation_targets = reference_targets + [Path('Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md')]
for p in presentation_targets:
    if not p.exists():
        continue
    text = p.read_text(encoding='utf-8')
    protected = text.replace('docs/reviewer/', '__DOCS_REVIEWER_PATH__/')
    updated = protected
    for old, new in replacements:
        updated = updated.replace(old, new)
    updated = updated.replace('__DOCS_REVIEWER_PATH__/', 'docs/reviewer/')
    p.write_text(updated, encoding='utf-8')

p = Path('Weall-Protocol/docs/audits/controlled_testnet_go_gate_closure_v1_5.md')
text = p.read_text(encoding='utf-8')
banner = (
    '> **Historical audit note:** this document records an earlier go-gate interpretation. '
    'It is superseded for current readiness claims by `generated/controlled_testnet_go_gate_v1_5.json`, '
    '`generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`, and '
    '`docs/reviewer/CURRENT_READINESS_STATEMENT.md`. Current generated state is NO-GO for '
    'controlled-testnet mechanism completion until the production-helper state-root/restart equivalence gate is proven.\n\n'
)
if not text.startswith('> **Historical audit note:**'):
    text = banner + text
text = text.replace('The current safe claim is:', 'The bounded claim at the time of this audit was:')
text = text.replace('After this audit, the repository may say:', 'At the time of this audit, the repository could say:')
p.write_text(text, encoding='utf-8')

p = Path('Weall-Protocol/README.md')
text = p.read_text(encoding='utf-8')
text = re.sub(
    r'The blocker catalog remains explicit: \d+ total entries, \d+ closed in repository, and \d+ open as external evidence or mainnet-hardening gates\.',
    'The blocker catalog remains explicit; read current total/open/closed counts directly from `generated/public_beta_blocker_report_v1_5.json`.',
    text,
)
p.write_text(text, encoding='utf-8')

p = Path('Weall-Protocol/docs/PUBLIC_BETA_BLOCKERS.md')
text = p.read_text(encoding='utf-8')
text = re.sub(
    r'\| Field \| Current meaning \| Expected value in this branch \|\n\| --- \| --- \| ---: \|\n(?:\|.*\n){8}',
    '| Field | Current meaning |\n| --- | --- |\n'
    '| `blocker_catalog_count` / `blocker_count` | Full blocker catalog kept visible for audit continuity. |\n'
    '| `closed_in_repository_count` / `closed_blocker_count` | Closed by repository evidence, generated artifacts, docs, or source-level UX gates. |\n'
    '| `remaining_blocker_count` / `open_blocker_count` | Still-open blockers before public beta can be claimed. |\n'
    '| `remaining_external_evidence_required_count` | Open blockers requiring independent or future evidence. |\n'
    '| `p0_open_count`, `p1_open_count`, `p2_open_count`, `p3_open_count` | Severity-bucket counts; read directly from the generated report. |\n',
    text,
)
p.write_text(text, encoding='utf-8')

p = Path('Weall-Protocol/scripts/check_public_claim_freshness.py')
text = p.read_text(encoding='utf-8')
old_docs = '''CURRENT_DOCS = [
    ROOT / "README.md",
    ROOT.parent / "README.md",
    ROOT / "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    ROOT / "docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md",
]
'''
new_docs = '''CURRENT_DOCS = [
    ROOT / "README.md",
    ROOT.parent / "README.md",
    ROOT / "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    ROOT / "docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md",
    ROOT / "docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md",
    ROOT / "docs/PUBLIC_BETA_BLOCKERS.md",
]
'''
if old_docs not in text:
    raise SystemExit('claim freshness CURRENT_DOCS anchor not found')
text = text.replace(old_docs, new_docs, 1)
insert_after = '''SAFE_NEGATION = re.compile(
    r"\\b(?:not|no|never|unclaimed|does not|must not|remain(?:s)? required|pending)\\b", re.IGNORECASE
)
'''
addition = '''FUNDING_REVIEW_FRAMING = re.compile(
    r"\\b(?:nlnet|first[- ]round|grant[- ]funded|grant update|funded (?:work|hardening|mainnet-readiness)|reviewer-facing|reviewer-visible|reviewer confidence|reviewer conclusion|reviewer setup|reviewer verification|reviewer evidence)\\b",
    re.IGNORECASE,
)
'''
if insert_after not in text:
    raise SystemExit('claim freshness regex anchor not found')
text = text.replace(insert_after, insert_after + addition, 1)
old_loop = '''            if MUTABLE_COUNT.search(line):
                findings.append(f"{path}:{lineno}: duplicated mutable count: {line.strip()}")
'''
new_loop = '''            if MUTABLE_COUNT.search(line):
                findings.append(f"{path}:{lineno}: duplicated mutable count: {line.strip()}")
            if ABSOLUTE_SECURITY.search(line) and not SAFE_NEGATION.search(line):
                findings.append(f"{path}:{lineno}: unqualified absolute-security claim: {line.strip()}")
            if FUNDING_REVIEW_FRAMING.search(line):
                findings.append(f"{path}:{lineno}: funding/repository-review framing in current-facing prose: {line.strip()}")
'''
if old_loop not in text:
    raise SystemExit('claim freshness loop anchor not found')
text = text.replace(old_loop, new_loop, 1)
p.write_text(text, encoding='utf-8')
PY

cd "$BACKEND"
python -m ruff format scripts/check_public_claim_freshness.py
python -m ruff check scripts/check_public_claim_freshness.py
python scripts/gen_release_evidence_manifest_v1_5.py
python scripts/gen_current_verified_claims.py
python scripts/compile_v2_spec.py
python -m ruff check scripts/check_public_claim_freshness.py
python -m ruff format --check scripts/check_public_claim_freshness.py
python scripts/gen_release_evidence_manifest_v1_5.py --check
python scripts/gen_current_verified_claims.py --check
python scripts/compile_v2_spec.py --check
python scripts/check_public_claim_freshness.py
python scripts/check_v15_public_readiness_artifacts.py
python scripts/check_reviewer_truth_boundaries.py
python -m pytest -q tests/test_release_docs_truth_sync.py tests/test_reviewer_language_cleanup.py tests/test_public_readiness_artifacts_v15.py

cd "$ROOT"
if git grep -n -i -E 'NLnet|first[- ]round|grant[- ]funded|grant update|funded (work|hardening|mainnet-readiness)|reviewer-facing|reviewer-visible|reviewer confidence|reviewer conclusion|reviewer setup|reviewer verification|reviewer evidence' -- \
    README.md \
    Weall-Protocol/README.md \
    Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md \
    Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md \
    Weall-Protocol/docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md \
    Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md \
    Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md \
    Weall-Protocol/docs/REVIEWER_EVIDENCE_INDEX.md \
    Weall-Protocol/docs/PUBLIC_BETA_BLOCKERS.md \
    Weall-Protocol/docs/legal/PUBLIC_CLAIMS_CHECKLIST.md \
    Weall-Protocol/docs/audits/controlled_testnet_go_gate_closure_v1_5.md \
    Weall-Protocol/docs/audits/late_stage_public_testnet_gap_inventory_v1_5.md \
    Weall-Protocol/docs/audits/public_beta_blocker_reframe_after_step3_step4_v1_5.md; then
  echo 'Forbidden funding/repository-review framing remains on presentation surfaces.' >&2
  exit 1
fi
if git grep -n -i -E 'local sustained-load testing reached approximately 2350 TPS|globally ready for 2350 TPS' -- \
    README.md Weall-Protocol/README.md Weall-Protocol/docs/reviewer Weall-Protocol/docs/PUBLIC_BETA_BLOCKERS.md; then
  echo 'Stale current-facing TPS wording remains.' >&2
  exit 1
fi

git diff --check
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git add -A
git diff --cached --check
git status --short
git commit -m 'Neutralize claim language and remove stale readiness wording'
git push origin HEAD:claim-hygiene-neutral-language
