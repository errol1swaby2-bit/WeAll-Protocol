# A01–A20 P1 closure plan

## Objective

Close the **P1 tier derived from the most recent comprehensive WeAll production-readiness audit**, the September 30, 2026 A01–A20 master audit.

This supersedes the obsolete 12-finding September P1 revalidation plan that initially occupied this branch.

The September 30 inventory contains 77 findings:

- 27 HIGH — already mapped to P0 and closed through merged PR #38;
- 34 MEDIUM — **this P1 closure scope**;
- 16 LOW — remain outside this P1 scope.

P1 is therefore defined here as **every MEDIUM finding in the A01–A20 master audit inventory**. Audit-local “Priority 1” ordering inside an individual Axx report does not replace the cross-audit severity tier.

## Authoritative audit source

Audit snapshot:

- audit date: `2026-09-30`
- audited commit: `cd7f10a8b62e9f5a3711f4263d04e3fd62f0d351`
- audited tree: `36a5868c72022f11a61bca8f48816852acccb1c9`
- total findings: 77
- HIGH/P0: 27
- MEDIUM/P1: 34
- LOW remaining: 16

Authoritative implementation baseline for this closure:

- branch: `main`
- commit: `61b1a81f624e7f5c81808aa4b580e3c2f8d55a06`
- tree: `a6b0a6e3506e6ff9f38fbf42454b4770ac7ac9a7`
- meaning: merged PR #38, A01–A20 HIGH/P0 closure

## P1 tracks

### P1-01 — Repository authority, reproducibility, reviewer bootstrap and route source truth

Findings:
`A01-F001`, `A01-F002`, `A01-F003`, `A17-F001`, `A17-F002`, `A17-F003`, `A19-F002`, `A19-F003`, `A19-F004`.

Closure objective:
make source promotion mechanically trustworthy, distinguish source-clean from machine-clean proof, eliminate or explicitly classify shadow API route authority, and provide one reproducible exact-ref reviewer path whose prerequisites and skips are explicit.

### P1-02 — Typed transaction semantics and all-canon semantic assurance

Findings:
`A02-F002`, `A16-F006`.

Closure objective:
make accepted signed payload semantics identical between schema validation and execution, then strengthen canon assurance beyond handler/schema presence toward executable semantic vectors.

### P1-03 — Persistence, durability and canonical-state publication

Findings:
`A03-F001`, `A03-F002`, `A14-F001`.

Closure objective:
reject stale persisted snapshots when newer durable history exists, give durable queue acknowledgements an explicit durability boundary, and prevent older reads from replacing newer canonical in-memory state.

### P1-04 — Consensus timeout and constitutional-slot validity

Findings:
`A05-F003`, `A06-F002`.

Closure objective:
rank timeout-certificate referenced QCs by real verifiable QC rank and make builder/BFT/follower treatment of future constitutional slots one coherent consensus rule.

### P1-05 — Transport/cryptographic identity and signature-profile policy

Findings:
`A07-F003`, `A13-F001`, `A13-F002`.

Closure objective:
fail closed on production TLS verification, canonicalize cryptographic authority identity across equivalent key encodings, and ensure signature-profile policy cannot silently fall back to an unintended profile.

### P1-06 — PoH evidence and anti-Sybil/collusion enforcement

Findings:
`A08-F002`, `A08-F003`.

Closure objective:
revalidate these findings under the P0-06 production human-authority scope lock. A finding may be scope-closed only if the unsafe positive authority path is genuinely unreachable in the production contract and exact tests prove no bypass. Do not invent missing privacy/uniqueness protocols merely to mark these closed.

### P1-07 — Economics, treasury, rewards and fee integrity

Findings:
`A10-F003`, `A10-F004`, `A11-F001`, `A11-F002`.

Closure objective:
align reward residual/bucket behavior with the authoritative policy, bind treasury cancellation to treasury-scoped authority, prevent value disappearance in FEE_PAY, and either enforce configured transfer fees exactly or fail closed on unsupported nonzero fee policy.

### P1-08 — API privacy and operator authorization

Findings:
`A12-F002`, `A12-F003`.

Closure objective:
make anonymous mempool status a bounded public projection and require explicit production operator authentication independent of loopback/reverse-proxy topology.

### P1-09 — Resource-exhaustion residuals

Findings:
`A15-F004`, `A15-F005`, `A15-F006`.

Closure objective:
make health/readiness constant/bounded-cost, bound public state snapshot work/response size, and revalidate `A15-F006` against the P0-01 one-shot transaction-identity closure. If P0-01 already removes the reusable failed-work primitive, close A15-F006 as already closed only with current executable evidence.

### P1-10 — Claims truth, repository messaging and browser credential custody

Findings:
`A18-F003`, `A18-F004`, `A19-F001`, `A20-F002`.

Closure objective:
make current claims consume the complete same-tree finding state, put the uniqueness/Sybil limitation at the point of verified-human claims, remove or qualify overbroad canon-conformance messaging, and establish an explicit browser session-custody model that does not persist raw bearer authority without a reviewed need.

## Adjudication rule

Every finding must finish as exactly one of:

- `already_closed_and_proven` — P0 or later work already eliminated the defect and current exact-head evidence proves it;
- `patched_and_proven` — a root-cause repair was required and exact-head evidence proves closure;
- `scope_closed_and_proven` — a reviewed production scope lock makes the unsafe capability unreachable and bypass evidence proves that boundary;
- `design_blocker` — a normative rule is genuinely missing and code must not invent it;
- `open` — not closed.

A historical green test, disabled feature, or nearby P0 patch is not sufficient by itself.

## First pass: current-source revalidation

Before changing protocol/runtime code:

1. trace each of the 34 finding paths against the post-P0 `main`;
2. identify findings already eliminated incidentally by P0;
3. reproduce every surviving defect with the smallest discriminating executable test;
4. record any finding whose source-audit premise no longer matches current source;
5. only then patch surviving findings.

The branch must preserve the finding IDs from the September 30 audit. Do not replace them with the older `P1-NET-*`, `P1-SEC-*`, or other September pre-A01–A20 identifiers.

## Closure evidence requirements

Per finding, closure evidence should include the audit-required negative/positive regression and, where applicable:

- proposer/follower/replay parity;
- restart persistence;
- two-node deterministic agreement;
- wrong-principal/right-principal authorization matrix;
- exact durability/readback behavior;
- bounded resource/work evidence;
- cryptographic identity/profile negative cases;
- generated API/spec/claim truth.

Whole-PR final gates:

1. all 34 MEDIUM/P1 findings adjudicated with no `open` or unresolved `design_blocker`;
2. P0 invariants remain closed;
3. dependency audit green;
4. canon lint green;
5. transaction/generated/V2/current-claim artifacts regenerated and current;
6. focused P1 matrix green;
7. complete backend suite green;
8. Reviewer Readiness green;
9. Web CI green;
10. Secrets Guard green;
11. temporary closure workflows removed;
12. final commit and Git tree recorded in exact-head evidence.

## Truth boundary

Closing this P1 effort means the 34 MEDIUM findings from the September 30 A01–A20 audit have been adjudicated and proven closed against the post-P0 implementation.

It does not close the 16 LOW findings, does not reactivate scope-closed Proof-of-Human authority, and does not by itself authorize public mainnet, public economics, or broader launch claims.
