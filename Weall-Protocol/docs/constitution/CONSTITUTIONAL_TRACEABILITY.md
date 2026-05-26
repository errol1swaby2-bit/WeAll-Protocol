# WeAll Constitutional Traceability Map — Draft 2

Status: genesis-bound draft commitment with partial enforcement.

This document maps the WeAll Genesis Constitution Draft 2 to protocol surfaces that future recursive audits must inspect. The Constitution Draft 2 is now hash-bound in the canonical production chain manifest and exposed through chain/status identity surfaces; many constitutional protections remain implementation targets until the linked code/tests enforce them end-to-end.

## Audit classification

Future audits should classify each constitutional requirement as one of:

1. **Already enforced** — code/tests enforce the requirement.
2. **Partially enforced** — some enforcement exists, but important paths remain incomplete.
3. **Aspirational / not yet implemented** — the Constitution states the target, but the current protocol does not enforce it yet.
4. **Direct contradiction** — code or documentation conflicts with the Constitution.
5. **Constitutional risk** — current behavior may enable capture, discrimination, privacy leakage, caste formation, or node/client authority confusion.

## Source hierarchy note

When the Constitution states a right or principle not yet enforced in code, recursive audits should treat the difference as an implementation gap, not as proof that the current codebase is intentionally violating its design.

## Traceability matrix

| Constitutional area | Protocol / product surfaces to audit |
|---|---|
| Article I — Founding Status | genesis config, chain manifest, protocol metadata, governance docs, status/operator surfaces, constitutional hash/version fields |
| Protocol authority | tx canon, domain appliers, admission, block replay, frontend capability gates, node/access surfaces, helper execution boundaries |
| Article II — Core Rights | account state, ban/lock flows, dispute sanctions, group removals, role suspensions, appeals, privacy surfaces, user-facing error copy |
| Equal civic standing | PoH tiers, anti-spam gates, reputation gates, role eligibility, group membership, governance electorate definitions |
| Right to voice | posting gates, group posting authority, moderation/dispute flows, banned/locked account behavior, appeal paths |
| Due process | dispute open/review/finalize flows, juror assignment, moderation sanctions, role removal, emergency actions, appeal records |
| Privacy and limited disclosure | PoH evidence commitments, reviewer-private evidence, media uploads, direct messages, dispute evidence, storage routes |
| Portability | healthy node access, node switching, account/session portability, chain identity, state verification, tx receipts |
| Appeal and correction | reputation mutation, dispute appeals, sanction reversal, verification reapply/recovery, group moderation appeals |
| Article III — Anti-Domination | governance proposal rules, group charter rules, moderation rules, dispute outcomes, constitutional review, forbidden amendment floor |
| Article IV — Direct Democracy | governance proposal/vote flows, group governance, quorum, supermajority rules, electorate definitions, deliberation windows |
| Article V — Proof of Humanity | async PoH, live PoH, bootstrap quorum limits, production quorum lock, privacy commitments, appeal/reapply paths |
| Article VI — Roles/Reputation | role/badge gates, validator/operator/juror authority, reputation updates, suspension/removal, service authority separation |
| Article VII — Disputes/Moderation | report/dispute lifecycle, juror/reviewer gates, evidence handling, sanctions, appealability, conflict-of-interest checks |
| Article VIII — Groups | group creation, membership, group-scoped posting, group treasury, group moderation, group charters, group self-governance limits |
| Article IX — Governance | proposal creation, voting, threshold policy, constitutional review, treasury/economics activation, protocol upgrade review |
| Article X — Nodes/Clients | node neutrality, frontend non-authority, healthy node manager, stale node warnings, access-node switching, client diagnostics |
| Article XI — Treasury/Economics | economics activation, fee policy, treasury spend, role-bound signers, civic/social/governance fee-free protections |
| Article XII — Emergency Powers | emergency pause/suspend paths, validator/operator emergency actions, dispute emergency sanctions, review windows |
| Article XIII — Amendments | constitution amendment tx types, quorum, supermajority, challenge window, immutable genesis declaration preservation |
| Article XIV — Interpretation | docs truth sync, frontend language, audit driver, known limitations, reviewer docs |
| Article XV — Genesis Commitment | genesis first record, public declaration surfaces, constitutional status page, project documentation |

## Immediate implementation gaps to track

1. The Constitution Draft 2 document is hash-bound in `configs/chains/weall-genesis.json` through `constitution_hash` and `constitution_version`.
2. The active constitution commitment is exposed in `/v1/status`, `/v1/chain/identity`, and `/v1/chain/genesis` as an auditable commitment, not as a claim that every article is fully enforced.
3. Constitutional amendment transaction types, protected rights-floor checks, and amendment history roots are not yet implemented.
4. Healthy node access is partially implemented and should continue to mature into multi-node comparison and switching.
5. Constitutional review of protocol upgrades, tx canon changes, PoH threshold changes, and role authority changes should be added before public governance activation.

## Batch 428 scope

Batch 428 added the Constitution and traceability map as source-controlled audit references and introduced a frontend healthy-node connection manager MVP. Batch 430 binds Draft 2 into the canonical production chain manifest and status surfaces. It still does not implement amendment txs, emergency-power limits, or the full protected rights floor.

Audit keyword: constitutional amendment tx types.
