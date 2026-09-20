# Preliminary M1–M3 Requirement Traceability Matrix

Truth boundary: this is a read-only baseline classification, not a closure verdict.

## Summary
- **M2 / implemented_claimed_evidence_missing_or_unbound: 9**
- **M2 / implemented_claimed_unbound_snapshot: 17**
- **M2 / obsolete_or_rescoped: 1**
- **M3 / contradicted_by_runtime_and_evidence_missing: 2**
- **M3 / implemented_claimed_evidence_missing: 22**
- **Spec-M1 / source_defined_not_runtime_verified: 755**

## M2 requirements
| ID | Source status | Audit disposition | Title |
|---|---|---|---|
| P0-01 | implemented | implemented_claimed_unbound_snapshot | Ordinary active keys cannot replace the recovery authority |
| P0-02 | implemented | implemented_claimed_unbound_snapshot | Prior active keys cannot cancel valid independent recovery |
| P0-03 | implemented | implemented_claimed_unbound_snapshot | Canonical failed-recovery accounting and rate limits |
| P0-04 | implemented_requires_operator_signature_rotation | implemented_claimed_unbound_snapshot | Guardian recovery retired on pinned v2 genesis states |
| P0-05 | implemented | implemented_claimed_unbound_snapshot | Encrypted case-scoped PoH and recovery evidence |
| P0-06 | implemented | implemented_claimed_unbound_snapshot | Reviewer evidence access revoked at closure |
| P0-07 | implemented | implemented_claimed_unbound_snapshot | Account-private-key persistence source regression fixed |
| P0-08 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Complete backend and frontend suites |
| P1-01 | implemented | implemented_claimed_unbound_snapshot | Tier 2 continuity recovery with 15 reviewers and 10 approvals |
| P1-02 | implemented | implemented_claimed_unbound_snapshot | Recovery reversal with fresh 25-reviewer panel and 20 approvals |
| P1-03 | implemented | implemented_claimed_unbound_snapshot | Evidence retention, deletion deadline, retries, and provider attestations |
| P1-04 | implemented | implemented_claimed_unbound_snapshot | Async reviewer decline replacement |
| P1-05 | implemented | implemented_claimed_unbound_snapshot | Async follow-up evidence lifecycle |
| P1-06 | implemented | implemented_claimed_unbound_snapshot | Actual Tier 2 reverification cases |
| P1-07 | implemented | implemented_claimed_unbound_snapshot | Tier-2-only responsibility replacement and safe withdrawal |
| P1-08 | implemented | implemented_claimed_unbound_snapshot | ACCT Tier 0 and Tier 1 gate corrections |
| P1-09 | rescoped | obsolete_or_rescoped | Institutional identity removed from M2 by formal architecture decision |
| P2-01 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Independent-browser async applicant and reviewer E2E |
| P2-02 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Independent-browser live applicant and reviewer E2E |
| P2-03 | implemented | implemented_claimed_unbound_snapshot | Async and live reviewer runbooks |
| P2-04 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Media interruption and reviewer replacement rehearsal |
| P2-05 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Backend restart and deterministic replay |
| P2-06 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Two-node state-root equality |
| P2-07 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Observer catch-up |
| P2-08 | implemented | implemented_claimed_unbound_snapshot | Requirement traceability |
| P2-09 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Implementation-freeze followed by evidence-only closure commit |
| P2-10 | evidence_required | implemented_claimed_evidence_missing_or_unbound | Stateful account custody create, verify, register, restart, restore, and protected-action E2E |

## M3 requirements
| ID | Source status | Audit disposition | Title |
|---|---|---|---|
| M3-P0-01 | closed | implemented_claimed_evidence_missing | Capture the correct protocol-wide or group electorate for every versioned voting round |
| M3-P0-02 | closed | implemented_claimed_evidence_missing | Make the first admitted final ballot immutable |
| M3-P0-03 | closed | implemented_claimed_evidence_missing | Use immutable per-round denominators with deterministic quorum refresh and no-decision expiry |
| M3-P0-04 | closed | implemented_claimed_evidence_missing | Do not expose a forbidden identity-to-ballot-choice mapping |
| M3-P0-05 | closed | implemented_claimed_evidence_missing | Keep validator authority separate from political eligibility |
| M3-P0-06 | closed | contradicted_by_runtime_and_evidence_missing | Preserve public group reads with backend-enforced participation gates |
| M3-P0-07 | closed | implemented_claimed_evidence_missing | Complete backend and frontend suites from the implementation freeze |
| M3-P1-01 | closed | implemented_claimed_evidence_missing | Tier-2 user creates a signed public post and reconciles finality |
| M3-P1-02 | closed | contradicted_by_runtime_and_evidence_missing | Independent Tier-2 user joins a public group through the canonical membership request |
| M3-P1-03 | closed | implemented_claimed_evidence_missing | Group member creates content while a nonmember retains public read access |
| M3-P1-04 | closed | implemented_claimed_evidence_missing | Signed report creates a public reviewable dispute and deterministic reviewer assignments |
| M3-P1-05 | closed | implemented_claimed_evidence_missing | Independent reviewers accept, attend and submit one final review ballot each |
| M3-P1-06 | closed | implemented_claimed_evidence_missing | Appeal uses the required fresh panel and produces an append-only final correction receipt |
| M3-P1-07 | closed | implemented_claimed_evidence_missing | Protected identity evidence remains excluded from broad civic routes |
| M3-P1-08 | closed | implemented_claimed_evidence_missing | Eligible Tier-2 user creates and comments on a no-action civic proposal |
| M3-P1-09 | closed | implemented_claimed_evidence_missing | Only eligible humans or group members in the active round can cast one final ballot |
| M3-P1-10 | closed | implemented_claimed_evidence_missing | Block-height close, tally and finalization create traceable receipts |
| M3-P2-01 | closed | implemented_claimed_evidence_missing | Non-skippable independent-browser multi-actor civic/governance journey |
| M3-P2-02 | closed | implemented_claimed_evidence_missing | Restart and deterministic replay preserve the complete M3 final state |
| M3-P2-03 | closed | implemented_claimed_evidence_missing | Two nodes converge on identical M3 state and receipts |
| M3-P2-04 | closed | implemented_claimed_evidence_missing | Observer catches up to the finalized M3 state without gaining authority |
| M3-P2-05 | closed | implemented_claimed_evidence_missing | M3 scope and requirement traceability are machine checked |
| M3-P2-06 | closed | implemented_claimed_evidence_missing | Implementation freeze and evidence-only direct child bind closure |
| M3-P2-07 | closed | implemented_claimed_evidence_missing | M3 mandatory journeys cannot be skipped or replaced by synthetic direct-apply proof |

## Spec-M1
The full 755-row Spec-M1 matrix is in the JSON and CSV outputs. All 755 rows remain `source_defined_not_runtime_verified` because the generated requirement register itself records `SPECIFICATION_DEFINED;IMPLEMENTATION_NOT_VERIFIED`.
