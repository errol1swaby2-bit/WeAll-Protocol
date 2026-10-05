from pathlib import Path
import json


def replace_exact(path, old, new, *, minimum=1, maximum=None):
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count < minimum or (maximum is not None and count > maximum):
        raise SystemExit(
            f"{path}: expected replacement count in [{minimum}, {maximum}], got {count}: {old[:100]!r}"
        )
    text = text.replace(old, new)
    p.write_text(text, encoding="utf-8")
    print(f"{path}: replaced {count} occurrence(s)")


def insert_once(path, anchor, insertion):
    replace_exact(path, anchor, insertion + anchor, minimum=1, maximum=1)


# 1) Remove the ambiguous shorthand that could be read as a global uniqueness claim.
old_checkpoint = (
    "Proof-of-Humanity checkpoint: **Tier 0 = account only**, **Tier 1 = native async verified human**, "
    "and **Tier 2 = native live verified human**. There is no required user-facing Tier 3. There is no required email, "
    "no required SMTP, no required DNS, and no required named hosting provider as PoH authority."
)
new_checkpoint = (
    "Proof-of-Humanity checkpoint: **Tier 0 = account only**. Tier 1 (native async review) and Tier 2 (native live review) "
    "remain implemented compatibility/rehearsal states, but the production profile sets "
    "`params.poh.human_authority_mode = scope_closed_pending_uniqueness_entropy`, so new positive human-authority "
    "creation/advancement is fail-closed. These tiers are not proof of global one-human uniqueness. There is no required "
    "user-facing Tier 3. There is no required email, no required SMTP, no required DNS, and no required named hosting "
    "provider as PoH authority."
)
for path in [
    "README.md",
    "Weall-Protocol/README.md",
    "Weall-Protocol/docs/PRODUCTION_POSTURE.md",
]:
    replace_exact(path, old_checkpoint, new_checkpoint, minimum=1, maximum=1)

old_tiers = (
    "**Tier 0 = account only**, **Tier 1 = native async verified human**, "
    "**Tier 2 = native live verified human**."
)
new_tiers = (
    "**Tier 0 = account only**; Tier 1/2 are implemented native review states, but production positive human authority "
    "is currently scope-closed by `params.poh.human_authority_mode = scope_closed_pending_uniqueness_entropy`; the tiers "
    "do not establish global one-human uniqueness."
)
for path in [
    "Weall-Protocol/docs/PRODUCTION_POSTURE.md",
    "Weall-Protocol/docs/PROTOCOL_VERSIONING_STRATEGY.md",
    "Weall-Protocol/docs/PRODUCTION_RUNBOOK_VALIDATORS.md",
]:
    replace_exact(path, old_tiers, new_tiers, minimum=1)

# 2) Make the current fail-closed seed-registry state explicit everywhere reviewers are directed.
seed_para = (
    "The checked-in public testnet seed registry is `configs/public_testnet_seed_registry.json`, the checked-in public testnet "
    "trust roots are `configs/public_testnet_trust_roots.json`, and the pinned testnet chain identity config is "
    "`configs/chains/weall-testnet-v1.json`. It is a repository-pinned discovery input for observer bootstrapping; it is not "
    "provider authority, validator authority, or proof of public beta readiness."
)
seed_para_new = seed_para + (
    " The current checked-in registry is intentionally fail-closed after the latest chain-identity change: "
    "`seed_registry_rotation_required=true`, `pq_resign_required_before_public_testnet=true`, and "
    "`seed_registry_signature` is empty until the operator-held ML-DSA re-signing ceremony."
)
replace_exact("README.md", seed_para, seed_para_new, minimum=1, maximum=1)

backend_seed = (
    "The checked-in public-testnet chain commitments, signed seed registry, trust roots, and validator endpoint evidence must "
    "match before boot proceeds. Endpoint advertisements are connection hints and freshness evidence; they do not grant validator authority."
)
backend_seed_new = (
    "The checked-in public-testnet chain commitments and trust roots must match, and the seed-registry signature gate must pass "
    "before public-testnet boot proceeds. The current checked-in seed registry is intentionally fail-closed pending operator-held "
    "ML-DSA re-signing after the chain-identity change; an absent signature is not readiness evidence. Endpoint advertisements are "
    "connection hints and freshness evidence; they do not grant validator authority."
)
replace_exact("Weall-Protocol/README.md", backend_seed, backend_seed_new, minimum=1, maximum=1)

current_state_old = (
    "Repository evidence includes public-only regression checks, signed/pinned observer discovery inputs, governance/dispute lifecycle tests, "
    "record-only protocol-upgrade tests, economics-lock tests, release hygiene, secret guard, generated artifact checks, and deterministic source/derivative validation."
)
current_state_new = (
    "Repository evidence includes public-only regression checks, pinned observer discovery inputs and signature-verification gates, "
    "governance/dispute lifecycle tests, record-only protocol-upgrade tests, economics-lock tests, release hygiene, secret guard, generated "
    "artifact checks, and deterministic source/derivative validation. The checked-in seed registry is intentionally fail-closed pending "
    "operator-held ML-DSA re-signing after the chain-identity change."
)
replace_exact(
    "Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md",
    current_state_old,
    current_state_new,
    minimum=1,
    maximum=1,
)

quickstart_old = (
    "Observer boot should use signed/pinned chain commitments, seed registry, trust roots, and endpoint evidence. Endpoint advertisements are "
    "connection hints and freshness evidence; they do not grant validator status."
)
quickstart_new = (
    "Observer boot requires pinned chain commitments and trust roots plus signature-gated seed-registry/endpoint evidence. The checked-in "
    "seed registry is intentionally fail-closed pending operator-held ML-DSA re-signing after the current chain-identity change; boot must "
    "not treat an absent signature as readiness. Endpoint advertisements are connection hints and freshness evidence; they do not grant validator status."
)
replace_exact(
    "Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md",
    quickstart_old,
    quickstart_new,
    minimum=1,
    maximum=1,
)

readiness_node_old = (
    "- **Node/operator surfaces:** readiness/status, signed discovery evidence, validator authority gating, observer status, release hygiene, and secret guard."
)
readiness_node_new = (
    "- **Node/operator surfaces:** readiness/status, pinned discovery inputs and signature-gated discovery evidence, validator authority gating, "
    "observer status, release hygiene, and secret guard. The checked-in seed registry remains fail-closed pending re-signing."
)
replace_exact(
    "Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    readiness_node_old,
    readiness_node_new,
    minimum=1,
    maximum=1,
)
replace_exact(
    "Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    "- **Observer boot:** `WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh` runbook with signed/pinned registry checks.",
    "- **Observer boot:** `WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh` runbook with pinned registry/signature checks; the current checked-in registry is intentionally fail-closed pending operator-held ML-DSA re-signing.",
    minimum=1,
    maximum=1,
)
replace_exact(
    "Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md",
    "Discovery uses signed/pinned protocol evidence; hosting providers are not authority.",
    "Discovery is designed around pinned protocol evidence with signature-verification gates; hosting providers are not authority, and the current checked-in seed registry remains fail-closed pending re-signing.",
    minimum=1,
    maximum=1,
)

for path in ["README.md", "Weall-Protocol/README.md"]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    text = text.replace("signed/pinned", "pinned/signature-gated")
    p.write_text(text, encoding="utf-8")

# 3) Explicitly distinguish closed A01-A20 P0 audit tracks from still-open release blockers carrying P0 severity labels.
namespace_note = (
    "## P0 namespace clarification\n\n"
    "The **A01-A20 P0/HIGH closure ledger** uses repository-remediation track IDs `P0-01` through `P0-12`; those tracks are closed at the scoped repository level represented by PR #38. "
    "That statement is distinct from public-release blocker severity labels such as `AUD-618-P0-001`, `AUD-618-P0-002`, `AUD-618-P0-003`, and `AUD-633-P0-004`. "
    "Those release blockers remain open and continue to keep `public_beta_ready=false`. Closing the A01-A20 P0/HIGH remediation ledger must not be read as closing every release blocker whose severity string contains `P0`.\n\n"
)
insert_once(
    "Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    "## What is implemented repository evidence\n",
    namespace_note,
)
insert_once(
    "Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md",
    "## Canonical sources\n",
    namespace_note,
)

# 4) Synchronize PoH design docs with the production scope lock.
native_path = "Weall-Protocol/docs/NATIVE_POH_BOOTSTRAP_LIMITS.md"
insert_once(
    native_path,
    "## Current model\n",
    "## Current production authority boundary\n\n"
    "The production profile currently commits `params.poh.human_authority_mode = scope_closed_pending_uniqueness_entropy`. Under that mode, new positive PoH human-authority creation/advancement and its schedulers fail closed. This document therefore describes compatibility/rehearsal behavior and future re-enablement requirements; it must not be read as claiming current production human uniqueness or an active production bootstrap path.\n\n",
)
replace_exact(
    native_path,
    "## Current model\n",
    "## Compatibility / rehearsal model\n",
    minimum=1,
    maximum=1,
)
replace_exact(
    native_path,
    "- Verified Person: native async human review.",
    "- Verified Person: native async human-review state in compatibility/rehearsal profiles; not proof of global one-human uniqueness.",
    minimum=1,
    maximum=1,
)
replace_exact(
    native_path,
    "- Trusted Verified Person: native live juror-attested review.",
    "- Trusted Verified Person: native live juror-attested state in compatibility/rehearsal profiles; not proof of global one-human uniqueness.",
    minimum=1,
    maximum=1,
)
replace_exact(
    native_path,
    "## Bootstrap problem\n",
    "## Bootstrap problem for any future re-enablement\n",
    minimum=1,
    maximum=1,
)
replace_exact(
    native_path,
    "This milestone may claim that WeAll has a protocol-native PoH architecture and implementation path that does not require centralized identity infrastructure for primary verification. It should not claim that the reviewer set is already fully decentralized unless a live network transcript proves it.",
    "This milestone may claim that WeAll contains protocol-native PoH transaction/review architecture and implementation paths that do not require centralized identity infrastructure as the primary verification mechanism. Production positive human-authority creation is currently scope-closed; this document must not be used to claim active production verified-human issuance, global uniqueness, or a fully decentralized reviewer set.",
    minimum=1,
    maximum=1,
)

human_path = "Weall-Protocol/docs/security/HUMAN_UNIQUENESS_AND_TIER0_LIFECYCLE.md"
replace_exact(
    human_path,
    "- PR #38 itself remains non-merge-ready until its final exact tree has current generated artifacts, current claim/evidence bindings, a green P0 assurance gate, the full backend suite, Reviewer Readiness, Web CI, and Secrets Guard.",
    "- any follow-up commit after an exact-head closure invalidates the prior exact-SHA/tree binding until generated artifacts, claim/evidence bindings, the P0 assurance gate, the full backend suite, Reviewer Readiness, Web CI, and Secrets Guard are green on the new head; the final exact SHA/tree belongs in PR #38 metadata.",
    minimum=1,
    maximum=1,
)

# 5) Narrow older truth/limitations language that could be mistaken for current external completion.
replace_exact(
    "Weall-Protocol/docs/TRUTH_BOUNDARY.md",
    "has reached private/local and external-observer rehearsal readiness",
    "has reached private/local reviewer rehearsal readiness and external-observer preparation; completion of a trusted external-observer run is not claimed",
    minimum=1,
    maximum=1,
)
replace_exact(
    "Weall-Protocol/docs/TRUTH_BOUNDARY.md",
    "| Proof of Humanity | Async/live PoH txs, APIs, frontend surfaces, review/finalization flows, and tier-gated follow-up flows exist and are test-covered in bounded suites. | PoH tests, reviewer tests, API/frontend source checks |",
    "| Proof of Humanity | Async/live PoH txs, APIs, frontend surfaces, and bounded review/finalization flows exist in compatibility/rehearsal code, while production positive human-authority creation remains scope-closed pending separately reviewed uniqueness and reviewer-entropy protocols. | PoH tests, reviewer tests, API/frontend source checks |",
    minimum=1,
    maximum=1,
)
replace_exact(
    "Weall-Protocol/docs/TRUTH_BOUNDARY.md",
    "private/external-observer rehearsal evidence",
    "private/local rehearsal evidence and external-observer preparation evidence",
    minimum=1,
)

known_path = "Weall-Protocol/docs/KNOWN_LIMITATIONS.md"
insert_once(
    known_path,
    "WeAll is pre-production. These limits should be disclosed in reviewer docs and grant materials.\n",
    "**Classification:** historical milestone notes with current cautionary value. Canonical current claims are `docs/CURRENT_VERIFIED_CLAIMS.md` and `docs/reviewer/CURRENT_READINESS_STATEMENT.md`; batch-specific statements below must not be treated as current readiness evidence.\n\n",
)
replace_exact(
    known_path,
    "- two-machine observer reachability,",
    "- runbooks and gates for two-machine observer reachability; completion requires a fresh external transcript,",
    minimum=1,
    maximum=1,
)
replace_exact(
    known_path,
    "- signed observer onboarding/account/networking/native-PoH-adjacent transaction submission,",
    "- signed observer onboarding requirements and verification tooling; completion is not claimed until the signature gate and external transcript pass,",
    minimum=1,
    maximum=1,
)
old_native_limits = (
    "Native async/live PoH exists as protocol-state transaction families, but the first live verified humans and jurors still require an auditable bootstrap path. "
    "This is a trust boundary, not a contradiction. Bootstrap authority must remain visible, limited, receipt-backed, and progressively replaceable by native juror-attested verification as the network gains enough reviewers."
)
new_native_limits = (
    "Native async/live PoH transaction/review families exist, but production positive human-authority creation/advancement is currently consensus-disabled under "
    "`scope_closed_pending_uniqueness_entropy`. The older bootstrap model is therefore a compatibility/future re-enablement design boundary, not a current production authority path. "
    "Any re-enablement requires separately reviewed uniqueness/privacy/adjudication and unpredictable reviewer-entropy design, plus an auditable bootstrap if one is still needed."
)
replace_exact(
    known_path,
    old_native_limits,
    new_native_limits,
    minimum=1,
    maximum=1,
)

# 6) Remove stale contingency language from the canonical P0 ledger without weakening its exact-head rule.
replace_exact(
    "docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md",
    "Closure remains contingent on the workflow-free exact tree passing the normal Backend CI, Reviewer Readiness, Web CI and Secrets Guard gates.",
    "That workflow-free exact-tree contingency was subsequently satisfied on the reconciled PR head recorded in PR #38 metadata. Any later follow-up commit must re-establish the same exact-head gates before reviewer handoff.",
    minimum=1,
    maximum=1,
)

# 7) Expand the current-document registry so critical PoH truth surfaces cannot silently drift again.
registry = "Weall-Protocol/docs/CURRENT_DOCUMENT_REGISTRY.json"
replace_exact(
    registry,
    '    "Weall-Protocol/docs/V15_IMPLEMENTATION_EVIDENCE_MAP.md",\n    "Weall-Protocol/docs/legal/*.md",',
    '    "Weall-Protocol/docs/V15_IMPLEMENTATION_EVIDENCE_MAP.md",\n    "Weall-Protocol/docs/NATIVE_POH_BOOTSTRAP_LIMITS.md",\n    "Weall-Protocol/docs/security/HUMAN_UNIQUENESS_AND_TIER0_LIFECYCLE.md",\n    "Weall-Protocol/docs/legal/*.md",',
    minimum=1,
    maximum=1,
)
replace_exact(
    registry,
    '    {"claim_scan": true, "classification": "CURRENT", "path": "Weall-Protocol/docs/NEW_NODE_OPERATOR_QUICKSTART.md"},\n',
    '    {"claim_scan": true, "classification": "CURRENT", "path": "Weall-Protocol/docs/NEW_NODE_OPERATOR_QUICKSTART.md"},\n    {"claim_scan": true, "classification": "CURRENT", "path": "Weall-Protocol/docs/NATIVE_POH_BOOTSTRAP_LIMITS.md"},\n    {"claim_scan": false, "classification": "HISTORICAL", "path": "Weall-Protocol/docs/KNOWN_LIMITATIONS.md"},\n',
    minimum=1,
    maximum=1,
)
replace_exact(
    registry,
    '    {"claim_scan": true, "classification": "CURRENT", "path": "Weall-Protocol/docs/production_readiness/final_truth_sync.md"},\n',
    '    {"claim_scan": true, "classification": "CURRENT", "path": "Weall-Protocol/docs/production_readiness/final_truth_sync.md"},\n    {"claim_scan": true, "classification": "CURRENT", "path": "Weall-Protocol/docs/security/HUMAN_UNIQUENESS_AND_TIER0_LIFECYCLE.md"},\n',
    minimum=1,
    maximum=1,
)

# Assertions against accidental reintroduction of the audited ambiguity.
audited = [
    "README.md",
    "Weall-Protocol/README.md",
    "Weall-Protocol/docs/PRODUCTION_POSTURE.md",
    "Weall-Protocol/docs/PROTOCOL_VERSIONING_STRATEGY.md",
    "Weall-Protocol/docs/PRODUCTION_RUNBOOK_VALIDATORS.md",
    "Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    "Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md",
    "Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md",
    "Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md",
    human_path,
    native_path,
]
for path in audited:
    text = Path(path).read_text(encoding="utf-8")
    if "Tier 1 = native async verified human" in text:
        raise SystemExit(f"stale PoH shorthand remains in {path}")
    if "signed/pinned" in text:
        raise SystemExit(f"ambiguous signed/pinned wording remains in {path}")

seed = json.loads(
    Path("Weall-Protocol/configs/public_testnet_seed_registry.json").read_text(
        encoding="utf-8"
    )
)
assert seed["seed_registry_signature"] == ""
assert seed["seed_registry_rotation_required"] is True
assert seed["pq_resign_required_before_public_testnet"] is True
print("documentation truth reconciliation complete")
