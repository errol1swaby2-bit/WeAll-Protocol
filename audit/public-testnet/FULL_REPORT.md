# WeAll public testnet — living master audit report

- Frozen implementation baseline: `6d3d69234415d294936d99e819367cff589ced3d` (main at branch creation).
- Scope: original audit, R0, recovered evidence, source re-audit, R1A candidate, and ongoing diagnostic audit.
- Deployment verdict: **NO-GO** for public participatory testnet. 81 provisional numbered findings (21 P0 / 60 P1), 8 separate candidates, 0 formally closed.
- Original experiment accounting: 167 (119 pass / 48 fail); fresh re-audit: 118 (100 pass / 18 fail); historical reruns: 53 (33 pass / 20 fail). Do not combine these as independent checks. Five separate model checks passed.
- The master evidence ZIP is preserved byte-for-byte; historical reports below are reproduced without silently changing their text. Later supplements supersede older recovery counts (TN-040 recovered; 81/81 titles). Reconstructed REINV definitions are not the missing original INV wording.
- Audit-only branch: no protocol or production configuration changes, no required-check or branch-protection changes, no implementation patch applied. Diagnostics report passing and failing assertions; they do not authorize release or enforce policy. Existing repository checks are unchanged.

## Latest audit checkpoint — R1B setup

**Status: diagnostic tests prepared; GitHub execution results pending.** R1A candidate remains uncommitted to protocol source. R1B traces planner `_access_conflicts` and `plan_parallel_execution` and the materialized merge boundary, with real imports and explicit fixture scopes. Test failure records are evidence, not proof of production exploit reachability. See the diagnostic job artifact and subsequent checkpoint updates. No finding is closed.

## Archive integrity

`evidence/WeAll_Master_Audit_Reaudit_Through_R1A.zip` SHA-256 `56a4b7b322edceb7810dc7655a94a7f6487bf50b3cd72eb93f59ac25cb84c587`; 71 entries, ZIP CRC verified locally. The archive includes original retrieved logs, test harnesses, source excerpts, the candidate patch, full reconstructed registries and earlier ZIPs. Original transcripts and 114 missing historical individual outcomes remain unavailable; replacement evidence is labeled as such.

## Preserved report sections

Below are the complete text of the selected original reports and supplements, in chronological evidence order. The ZIP remains the definitive unmodified evidence snapshot.


---

## Preserved file: `audit/EARLY_PHASES_RECOVERED_HISTORY.md`

# Early audit phases — recovered historical descriptions

Baseline `6d3d69234415d294936d99e819367cff589ced3d`. These are retrieved conversation-history summaries, **not** original reports or source-verification in this packaging turn. Do not use them as a substitute for the missing transcripts. November 19–20 2026.

| Phase | Available historical material |
|---|---|
| 0 | Initial indexing: 2,873 tracked files; 236 canonical transaction types; 295 backend source files; 1,170 backend tests; 143 frontend files; 125 deployment/release files. Initial 15 blockers and 8 findings TN-001–008; architecture and deployment checklist reported; NO-GO. |
| 1A | Transaction-admission tracing; observer forwarding (TN-003), Genesis ML-DSA key incompatibility (32-byte vs 1,952-byte; 64-hex generator, reported TN-009), registration verification ordering (TN-010). |
| 1B | Consensus phases and quorum; first canonical solo finality (TN-011); zero Genesis timestamp and clock enforcement (TN-012); observer/validator replay divergence (TN-013); procedural-time regression (TN-014). |
| 1C | Raw session bearer in signed history (TN-015); predictable reviewer selection and public-testnet compatibility mode (TN-016); scalar reputation remains operative (TN-017); legacy verification-tier inconsistency (TN-018); recovery protections present. 18 findings reported. |
| 1D | Attributable ballots (TN-019); automatic bans bypass severe-sanction safeguards (TN-020); public-testnet governance/ballot profile discrepancy (TN-021); proposal-defined thresholds (TN-022); tally inconsistency (TN-023); group membership removal due process (TN-024). 24 findings reported. |
| 1E | CID/digest conflicts (TN-025); retained replacement digest (TN-026); storage capacity bypass (TN-027); premature deletion attestations (TN-028); aggregate isolation gaps (TN-029); untrusted MIME (TN-030). |
| 1F | Economic activation (TN-031); transfer identifier collision (TN-032); reward conservation (TN-033); readiness reporting (TN-034); storage payout (TN-035); supply reconciliation (TN-036). 36 findings: 20 P0, 16 P1. |
| 2 | 60 invariants historically reported; original definitions not recovered. |
| 3–4 | Adversarial and divergence analysis reported; complete original phase narratives and results not accessible. |
| 5A | Historical summary: 10 checks, 6 passed, 4 failed. Original harness/log missing. |
| 5B | 22 source/predicate checks and 5 separate model checks now preserved with text-extracted harness and result log. |
| 5C | 31 checks now preserved with text-extracted harness and result log. |
| 5D–5E | Original reports and execution records not recovered. |
| 5F | Historical summary: 30 checks, 28 passed, 2 failed; TN-031 reproduced at predicate level, TN-043 partial synchronization commitment source-confirmed. Original execution record missing. |
| 6A | Reverse authority tracing reported complete; original detailed report missing. |
| 6B | Detailed report pasted by user, transcribed in this archive. |
| 6C–6D | Current conversation reports accessible; detailed reconstruction and original R0 artifacts in this archive. |

## Monetary policy context from Phase 1F
The visible fragment of the Phase 1F report states 21,000,000 WCN maximum supply, zero Genesis balances, eight decimals, 20-second target blocks, ten-minute issuance interval, 30 blocks per issuance epoch and initial 100 WCN epoch issuance. The remainder of the original table and tracing is missing. Later conversation history refers to changed tokenomics targets; these are not silently merged with the pinned implementation or treated as deployed policy. The Phase 5B harness and saved logs preserve their own model inputs.

## Cumulative counts
81 provisional IDs, 21 P0 and 60 P1, 60 invariants, 167 previously reported checks (119 pass, 48 fail), no closures. Original Phase 0–5 reports remain required to verify all entries, especially TN-040, and reconstruct the complete invariant list. Phase count subtotals must not be combined without reconciling exactly which checks were counted and whether model checks were included.


---

## Preserved file: `audit/PHASE_6B_DETAILED_REPORT.md`

# Phase 6B — Recursive cross-domain failure analysis

Baseline: `6d3d69234415d294936d99e819367cff589ced3d`. Audit mode: strictly read-only.

**Provenance:** detailed plain-text transcription of the Phase 6B report pasted by the user in the current conversation. Interactive graphics are transcribed into text; Markdown links are retained through the source index. This is not a new reproduction.

This phase examines vulnerabilities that emerge not from individual components malfunctioning, but from different components operating under incompatible definitions of authority.

## 1. Human verification and governance eligibility

Source-confirmed inconsistency — pending production reachability verification.

WeAll includes a canonical function, `effective_poh_tier()`, that determines a participant's actual verification status. It distinguishes active, expired, revoked, suspended and challenged identities. However, the governance electorate construction functions read the account's legacy `poh_tier` field directly.

| Verification condition | Effective PoH tier | Potential legacy tier |
|---|---:|---:|
| Active Tier 2 | 2 | 2 |
| Expired Tier 2 | 1 | 2 |
| Suspended | 0 | 2 |
| Under challenge | 0 | 2 |
| Revoked | 0 | 0 |

The legacy value can therefore overstate effective authority when status and tier are not fully synchronized. The normal expiration scheduler updates the mirrored account record, mitigating part of this concern. Existing electorate snapshots and other status transitions still require separate verification. Affected invariants: INV-019, INV-027 and INV-029.

Sources: `runtime/poh/state.py:200–279`; `runtime/apply/governance.py:647–735`.

## 2. Dispute accountability and reviewer eligibility

Candidate defect — Accountability enforcement inconsistency.

When a juror fails to complete an assigned dispute vote, `_record_dispute_juror_accountability()` records the failure and modifies the participant's account-level eligibility. The shared reviewer-lane authorization function, however, evaluates a different collection of records.

Accountability subsystem: dispute juror eligibility = False (missed voting obligation recorded). Reviewer authorization: reviewer lane active = True (existing role record remains active). A similar inconsistency exists within Proof-of-Humanity reviewer accountability.

| Subsystem | Accountability mutation |
|---|---|
| Dispute resolution | `dispute_juror_eligible = False` |
| Proof-of-Humanity | `poh_reviewer_eligible = False` |
| Reviewer responsibilities | Evaluates role and lane records |
| Reputation role activation | Evaluates separate versioned eligibility rules |

The shared lane predicate does not independently inspect either of those account-level accountability flags. This creates a potential discrepancy between a sanction being recorded and that sanction becoming operationally effective. The appropriate security requirement is that a participant cannot continue exercising an institutional responsibility after a legitimate suspension has taken effect.

Sources: `runtime/apply/dispute.py:3342–3398`; `runtime/reviewer_responsibilities.py:164–198`; `runtime/apply/poh.py:2220–2280`.

## 3. Dispute panel contraction

Candidate defect — Constitutional quorum degradation.

The dispute resolution subsystem recalculates its required voting threshold using the currently eligible reviewer population. Under the existing version-one policy, reductions in eligible panel membership can consequently reduce the required quorum.

Illustrative seven-juror panel: remaining eligible jurors 7; dynamic quorum 5; original panel quorum 5. Threshold comparison derived from the current integer quorum function. Quorum alone does not establish verdict approval.

The source already contains a stronger version-two protection that preserves the original panel threshold and prevents automatic resolution when the lawful panel becomes incomplete. However, this protection is explicitly dormant pending a separately authorized activation. That confirms an important distinction between implemented safeguards and operational safeguards. A complete adversarial reproduction involving reviewer withdrawal, panel replacement and subsequent verdict execution remains outstanding.

Source: `runtime/apply/dispute.py:837–983`.

## 4. Emissary elections and treasury authority

Potential high-impact candidate defect — Candidate eligibility.

The group emissary election implementation has an explicit protection against seating candidates when no valid ballots were submitted. The newer election policy also enforces a frozen participation quorum. However, candidate eligibility is a separate concern.

The election creation handler normalizes the supplied candidate identifiers. The finalization handler retrieves those identifiers, calculates STV winners and assigns the resulting individuals as group and treasury signers. I did not locate an independent candidate eligibility check in either inspected handler.

Candidate registration (identifiers supplied) → election (participation quorum enforced) → STV calculation (winning candidates determined) → institutional seating (group emissaries replaced) → treasury authority (treasury signers replaced).

| Candidate condition | Enforcement established? |
|---|---|
| Registered account | Not established at seating |
| Current group membership | Not established at seating |
| Active Tier-2 verification | Not established at seating |
| Current reputation eligibility | Not established at seating |
| Account suspended during election | Not established at seating |

Subsequent signer authorization checks provide additional protections, including effective PoH validation. Consequently, seating an ineligible individual does not necessarily grant them usable spending authority. Nevertheless, an election that replaces legitimate signers with unavailable or ineligible identities could potentially leave a treasury unable to reach its required signature threshold. This is both an institutional integrity concern and an availability concern.

Sources: `runtime/apply/groups.py:1478–1574`, `1755–1947`.

## 5. Account recovery and consensus authority

The account recovery implementation correctly performs extensive credential replacement.

Established recovery behavior: previous transaction-signing keys revoked; previous registered devices revoked; previous sessions revoked; new account-signing authority installed; new offline recovery authority installed; authority generation incremented; temporary post-recovery restrictions established.

Cross-domain authority still requiring verification: validator consensus keys; existing operator authority; previously assigned reviewer responsibilities; pending treasury signature obligations.

Account recovery replaces account-level authority, but consensus and institutional roles maintain additional authority records. These records may intentionally use separate keys and lifecycle requirements. Automatically removing validators during account recovery could itself compromise consensus availability. The outstanding requirement is therefore not unconditional revocation of every responsibility. It is an explicit, safe transition policy for each responsibility affected by an account recovery.

Source: `runtime/apply/identity.py:1258–1367`.

## 6. Intra-block authorization consistency

Potential critical candidate defect — Stale transaction authorization.

Block admission performs signature, nonce and eligibility checks before sequential transaction execution begins. The admission function adjusts each signer's nonce cursor to account for preceding transactions, but does not reconstruct every preceding state mutation. This creates a potentially significant boundary involving transactions that change authorization within a block.

Initial ledger: signing key active. Block admission: both transactions evaluated against the initial signing authority. Transaction 1: signing key revoked. Transaction 2: previously admitted transaction reaches its execution handler. Does the second transaction revalidate the modified signing authority?

The inspected execution loop does not visibly repeat the complete signature-admission process before each domain mutation. This warrants particularly careful investigation across key revocation, account restrictions, role suspension and treasury signer replacement. Both block construction and follower replay use the pre-execution admission mechanism. Consequently, this could represent a deterministic authorization failure rather than a disagreement between honest nodes. The exact intended effective point of revocation must also be established: immediate transaction ordering or the subsequent block boundary. No signed reproduction was performed.

Sources: `runtime/block_admission.py:323–477`; `runtime/apply/identity.py:547–591`; `runtime/block_replay.py:690–770`.

## 7. Cross-domain risk matrix

Potential consequences of inconsistent authority propagation:

| | Identity | Justice | Governance | Consensus | Economics |
|---|---|---|---|---|---|
| Identity | H | H | H | H | H |
| Reputation | M | H | H | M | M |
| Justice | H | H | M | M | L |
| Governance | M | M | H | H | H |
| Consensus | H | H | H | H | H |
| Recovery | H | M | M | H | H |

H = high, M = moderate, L = low. Qualitative architectural impact assessment, not measured exploit probabilities.

The recurring architectural weakness is fragmented authority representation: several subsystems maintain separate records describing whether an individual possesses a particular responsibility. The existence of those separate records is not inherently problematic. The danger arises when their respective state transitions and authorization predicates disagree.

## 8. Cumulative audit status

81 provisional numbered findings; 60 protocol invariants; 21 P0; 60 P1; 167 previously reported experimental checks (119 passed, 48 failed); 0 resolved. The additional candidate defects were not incorporated into the numbered register before consolidation to avoid duplication.

## 9. Remaining audit work

Phase 0 codebase indexing; Phase 1 execution tracing; Phase 2 invariant extraction; Phase 3 adversarial analysis; Phase 4 divergence analysis; Phase 5 executable reproduction; Phase 6A reverse authority tracing; Phase 6B cross-domain failure analysis; next Phase 6C consolidation and severity reassessment; Phase 6D completeness and final report.

## Audit limitations

This segment consisted exclusively of static source inspection. No additional executable tests were performed, and the constitutional specification documents were not reopened. The qualitative impact classifications are provisional audit judgments. No repository files, configurations, commits or operational infrastructure were modified. Public testnet deployment verdict: NO-GO.


---

## Preserved file: `audit/PHASE_6C_AND_6D_DETAILED_REPORT.md`

# Phase 6C — Consolidation and severity reassessment

Baseline `6d3d69234415d294936d99e819367cff589ced3d`; strictly read-only.

Provenance: plain-text rendering/reconstruction of the reports visible in the current conversation. All numerical values and substantive observations below are carried forward from those reports. Interactive graphics are rendered as prose or tables. For the original numbered register and all titles, see ALL_FINDINGS.md and r0/master_register.tsv; no titles have been discarded. This is not a newly executed audit.

## 1. Objective and cumulative baseline

The objective is to distinguish individual implementation defects from systemic architectural weaknesses and determine which constitute genuine public testnet deployment blockers. A blockchain can achieve deterministic consensus while consistently executing constitutionally unauthorized decisions. WeAll must protect against both computational and institutional failure.

81 provisional findings; 60 protocol invariants; 21 P0 and 60 P1; 167 previously reported experimental checks, 119 passed (71.3%) and 48 failed (28.7%); zero resolved. These are historical totals, not independently verified anew. Phase 5B and 5C experimental records were recovered and production source files were reopened at the exact audit baseline. The complete itemized register was not initially recoverable; no revised finding totals or premature closures were invented.

## 2. Revised severity and evidence methodology

| Severity | Classification criteria |
|---|---|
| P0 | Consensus failure, unauthorized institutional authority, irreversible state corruption or catastrophic network failure |
| P1 | Material security, constitutional, availability or integrity failure |
| P2 | Contained failure with limited consequences and a credible recovery mechanism |
| P3 | Maintainability, diagnostics, documentation or minor operational deficiencies |

| Evidence level | Description |
|---|---|
| E0 | Architectural hypothesis |
| E1 | Static source confirmation |
| E2 | Executable function-level reproduction |
| E3 | Production transaction-path reproduction |
| E4 | Independent multinode reproduction |

A critical architectural defect supported by E1 evidence warrants investigation before deployment but must not be described as an E4-confirmed exploit. An implemented safeguard is not an operational safeguard until its activation and enforcement are established.

## 3. Consolidated architectural failure families

The following ten categories are remediation families, not replacements for the 81 findings. Identity (PoH and recovery), reputation (eligibility and sanctions), governance (electorates and voting), justice (jurors and disputes), treasury and consensus all depend on compatible cross-domain authority enforcement.

| Family | Architectural weakness | Potential severity |
|---|---|---|
| CF-01 | Fragmented authority evaluation | P0 |
| CF-02 | Stale transaction authorization | P0 |
| CF-03 | Constitutional procedure bypass | P0 |
| CF-04 | Consensus and finality inconsistency | P0 |
| CF-05 | Helper execution and serial equivalence | P0 |
| CF-06 | Network trust and peer discovery | P0 |
| CF-07 | Monetary conservation and activation | P0 |
| CF-08 | Reputation accountability and reversibility | P0–P1 |
| CF-09 | Persistence and operational recovery | P0–P1 |
| CF-10 | Deployment configuration and assurance | P0–P1 |

## 4. CF-01 — Fragmented authority evaluation

Potential critical deployment blocker. The Genesis Constitution states that service authority must originate from explicit role assignments, elections, eligibility, protocol state or another constitutional process. Multiple representations of authority do not necessarily evaluate the same conditions:

| Responsibility | Authority representation |
|---|---|
| Governance participation | Legacy account PoH tier |
| Effective human verification | Canonical PoH status |
| Reviewer participation | Juror role and lane records |
| Reviewer accountability | Account-level eligibility flags |
| Treasury authority | Signer assignments and authorization predicates |
| Account control | Active cryptographic credentials |

Newly established dependency: group emissary election creation imports `_active_group_member_ids()` from governance and uses it to construct the version-one election electorate. The function reads the legacy PoH tier. Canonical status expiration or suspension may therefore leave a legacy Tier 2 mirror affecting both governance and emissary electorate construction. This should be considered alongside TN-018, subject to comparison with its original definition.

Required correction: canonical, domain-specific authority predicates derived from committed state. Historical snapshots must retain their explicitly specified semantics without permitting obsolete authority to be unintentionally exercised. Evidence: E1, production reachability unverified. Sources: `runtime/poh/state.py:200–279`, `runtime/apply/governance.py:647–735`, `runtime/apply/groups.py:1478–1574`.

## 5. CF-02 — Stale transaction authorization

Potential critical deployment blocker. Domain dispatcher inspection establishes a mitigating protection: certain authorization checks do occur during execution, including post-recovery restrictions and founder authority expiration. The inspected wrappers do not establish complete cryptographic reauthorization against the evolving ledger.

| Boundary | Reassessment |
|---|---|
| Initial signature verification | Implemented |
| Sequential nonce admission | Implemented |
| Atomic state mutation | Implemented |
| Apply-time recovery restriction | Implemented |
| Apply-time founder expiration | Implemented |
| Apply-time signing-key revocation | Not established |

Illustration: key is initially active; transaction 1 revokes it; transaction 2 already signed by that key reaches execution. Under initial-state authorization, potentially accepted; under evolving-state authorization, rejected against updated authority. This assumes transaction-order revocation and is not an executed production reproduction. The intended effective boundary (transaction order versus next block) must first be established, then consistently enforced by leader construction, follower replay and helpers. Sources: `runtime/block_admission.py:323–477`, `runtime/domain_dispatch.py`, `runtime/apply/identity.py:547–591`.

## 6. CF-03 — Constitutional procedure bypass

Related findings: TN-020 automatic bans and severe-sanction procedures; TN-066 insufficient quorum bounds; TN-071 inconsistent governance approval semantics; TN-072 nonbinary vote-counting inconsistency; panel contraction and reviewer accountability candidates. Phase 5B predicates produced different early/deadline outcomes under the same illustrative voting conditions.

The source documents stronger version-two initial panel protection as version gated, with no current governance activation path. Illustrative seven-juror panel: v1 dynamic quorum for remaining eligible 7/6/5/4/3/2/1 is 5/4/4/3/2/2/1; original floor is 5. V2 also requires panel completeness. Legitimate withdrawal must remain possible; quorum protection cannot compel voluntary service. Source: `runtime/apply/dispute.py:837–983`. Quorum alone is not verdict approval.

## 7. CF-04 and CF-05 — Consensus integrity and helpers

Recovered Phase 5C failures: TN-050 missing timestamp leaves request window open; TN-052 ancestor/descendant write conflicts and ancestor-read/descendant-write conflicts not detected, slash aliases not recognized; TN-078 conflicting manifest overrides committed block interval; unnumbered candidate explicit zero finality treated as absent. These were isolated functions and dependency fixtures, not independent production validators.

Helper A writes `accounts/x` with balance 10; helper B writes `accounts/x/balance` with 20. A→B produces 20; B→A produces 10. Even with deterministic production merge ordering, missed conflicts may violate serial equivalence. The helper safety spec requires deterministic partitioning, canonical ordering, deterministic merging and serial equivalence. Production merge-order divergence is not established; closure requires production-bound evidence.

## 8. CF-06 — Network trust and peer discovery

Separate discovery, authenticated peer identity and acceptance of consensus information. Related findings TN-001 unsigned seed registry; TN-002 Cloudflare registry verification; TN-003 observer forwarding; TN-037 peer-store saturation; TN-039 temporal advertisement validation; TN-041 peer persistence failure reporting. Recovered experiments demonstrate saturated store, zero validity-field and error-reporting failures, not network-wide eclipse. Potential chain: untrustworthy discovery → saturation → reduced access to new peers → isolation risk → inability to synchronize independently. Adversarial network testing is necessary.

## 9. CF-07 — Monetary conservation and economic activation

Maximum-supply and duplicate-epoch controls are meaningful, not proof of subsequent economic transaction integrity. Phase 5B distribution results:

| Initial aggregate | Debit | Credit | Result |
|---:|---:|---:|---|
| 100 | 50 | 50 | 100 |
| 100 | 50 | 60 | Rejected |
| 100 | 50 | 40 | 90 |
| 100 | 50 | 0 | 50 |

TN-033 concerns handler-level conservation. Unauthorized scheduler/production reachability remains outstanding. Independent controls required for supply cap, issuance authorization, conservation, treasury authority and constitutional activation. A demonstrably locked or unreachable mechanism may be a conditional deployment blocker, not resolved merely because locked.

## 10. CF-08 — Reputation accountability and reversibility

TN-075: reversing original delta does not necessarily undo actual applied effect under bounds. Example normalized initial 0.95, event +0.2, after clamp 1.0, reverse original delta to 0.8, residual -0.15. Symmetric negative case results in +0.15 residual. Incorrect reversal can prolong exclusion after successful appeal. Required deterministic correction accounting for saturation, intervening events and provenance. Provisional P1 with potential P0 consequences if incorrect state triggers constitutionally unauthorized sanctions.

## 11. CF-09 and CF-10 — Persistence and deployment assurance

| Security boundary | Required evidence |
|---|---|
| Clean installation | Independent fresh-clone deployment |
| Persistent state | Verified crash recovery |
| Consensus history | Cryptographically authenticated finality |
| Public configuration | Consistent canonical network parameters |
| Genesis authority | Verified activation and expiration |
| Frontend | Complete real-user acceptance rehearsals |
| Network participation | Independent discovery and synchronization |
| Recovery | Demonstrated credential and responsibility transitions |

Automated integration success alone cannot establish all deployment requirements.

## 12. Deployment classification and remediation order

Private development network permitted for controlled testing; controlled external rehearsal conditional; public observer not cleared; public participatory testnet NO-GO; mainnet NO-GO. Proposed order: (1) consensus, finality, deterministic execution, (2) cryptographic authority and admission, (3) identity/PoH/eligibility, (4) justice and sanctions, (5) governance/elections, (6) reputation accounting, (7) economics and treasury, (8) networking/persistence/recovery, (9) frontend and deployment assurance, (10) independent adversarial revalidation. This is a proposed dependency order, not authorization to modify the repository.

Phase 6C partial, original register reconciliation pending; zero new executions and zero modifications. NO-GO.

# Phase 6D — Final production-readiness assessment

Baseline unchanged; read-only. Executive assessment: public participatory testnet NO-GO. 81 provisional findings, 60 invariants, 21 P0, 60 P1, ten remediation families, zero closed. WeAll has meaningful implemented consensus, human verification, governance, dispute, reputation and monetary mechanisms. Interactions can still yield unauthorized or inconsistent outcomes.

## Specification authority

Documents referenced in the previous assessment: Genesis Constitution v0.1 (rights and limits), V2 full-scope specification (integrated design), V1.5 implementation evidence map (completeness), reputation matrix plan (integrity and accountability), helper consensus spec (deterministic parallel execution), Master Audit Driver (method). The V2 document was reported marked `V2_0_FIRST_DRAFT_NOT_AUTHORIZED` and aligned to earlier revision `63629d71`; Constitution marked draft for review. No inference of ratification or implementation completeness from a design document alone.

## Findings register reconstruction

80 of 81 labels (98.8%); 21/21 P0 and 59/60 P1 labels. TN-040 remains reserved; title not recovered. Full original evidence narratives are missing for some findings. The entire numbered list and acceptance criteria are preserved in ALL_FINDINGS.md and r0/master_register.tsv. Previously inferred P1 classification must be rechecked against originals. All 21 retain provisional P0 classification, not claims of proven production exploits.

## Experimental reconciliation

167 historical checks, 119 pass and 48 fail. Directly recovered Phase 5B: 14 pass/8 fail (22); Phase 5C: 19 pass/12 fail (31). Together 53 source-level checks and 20 failed assertions. Phase 5B also 5 separate model passes. Failed assertions: TN-033,037,039,041,050,052,066,071,072,075,078, ADV-006, explicit-zero-finality candidate. Exact results in the two saved evidence logs; harnesses now text-extracted separately in this package. Neither the sum of model/source checks nor failures should be treated as counts of unique production exploits.

## Final source-level verification

| Function | Assessment |
|---|---|
| `admit_block_txs()` | nonce sequencing established; evolving signing authority requires further verification |
| `detect_materialized_overlap()` | exact path conflicts but not hierarchical conflicts |
| `procedure_height()` | explicit zero falls back to potentially optimistic height |
| `runtime_block_clock_policy()` | enabled manifest policy takes precedence over committed state |

The four reopened boundaries concern inconsistent authorization, execution and premature constitutional procedure progression. See EVIDENCE_INDEX.md for pinned links and the retrieved Phase 5 records for executable evidence.

## Constitutional compliance assessment

Mappings identify potential noncompliance, not definitive violations of entire articles.

| Article | Relevant concerns |
|---|---|
| I — Constitutional supremacy | Unauthorized governance/execution |
| II — Core rights | Automatic sanctions, privacy, portability |
| III — Anti-domination | Institutional capture and procedural manipulation |
| IV — Direct democracy | Electorate integrity and ballot confidentiality |
| V — Proof-of-Humanity | Uniqueness and verification consistency |
| VI — Roles and reputation | Stale eligibility and reversal |
| VII — Disputes and review | Panel contraction and sanctions |
| VIII — Groups | Membership and authority |
| IX — Governance | Quorum, deliberation, proposals |
| X — Infrastructure | Node neutrality and historical verification |
| XI — Economics | Monetary and treasury integrity |
| XII — Emergency powers | Limits on extraordinary authority |
| XIII — Amendments | Versioning and approval thresholds |

Severe-sanction target requirements reported from V2: ordinary disputes 7 jurors/5 approvals; serious disputes 15/10; constitutional disputes/severe sanctions 25/80%; severe sanctions fresh-panel appeal before enforcement unless expressly waived under DSP-210 conditions. Coordinate automatic-ban and panel-contraction remediation; reputation must not circumvent due process. These are reported target requirements, subject to the applicable authorized specification.

## Systemic risk assessment

Qualitative impact, not measured exploit probability or implementation completeness: critical (5/5) consensus/finality, cryptographic authorization, governance/justice, identity/privacy; high (4/5) parallel execution, networking, reputation, persistence/recovery, economics; elevated (3/5) frontend reliability. Recursive chain: identity inconsistency → institutional eligibility inconsistency → procedural inconsistency → canonical execution → future decisions based on compromised state. Consensus alone cannot prevent this.

## Proposed release gates

| ID | Gate |
|---|---|
| G01 | Canonical consensus and finality |
| G02 | Deterministic execution and replay |
| G03 | Cryptographic authority and credential security |
| G04 | Human uniqueness and verification |
| G05 | Reputation integrity and reversibility |
| G06 | Constitutional justice and appeals |
| G07 | Governance and ballot integrity |
| G08 | Treasury and economic isolation |
| G09 | Private evidence and media security |
| G10 | Independent peer discovery |
| G11 | Persistence and disaster recovery |
| G12 | Helper and serial execution equivalence |
| G13 | Complete frontend acceptance |
| G14 | Independent adversarial review |
| G15 | Reproducible deployment and release authorization |

Zero composite gates formally cleared; individual passing mechanisms do not independently clear a composite gate.

## Proposed remediation program

R0 audit preservation: freeze findings, references, evidence and candidates. R1 consensus foundation: finality, time, deterministic admission/replay/helpers. R2 identity and authority: credentials, eligibility and privacy. R3 constitutional justice: sanction provenance, jurors, accountability and appeals. R4 democratic governance: electorate, quorums, ballots, elections, amendments. R5 reputation/economics: correction, conservation, treasury and activation. R6 infrastructure/product: networking, storage, persistence, recovery, APIs and frontend lifecycle. R7 independent revalidation: full regressions and controlled fresh-install multinode rehearsals. Each phase requires implementation evidence, negative tests, specification mapping and exact-commit validation.

## Final audit status and limitations

Phases 0–6B previously reported done; 6C index reconstructed and 6D assessment delivered but reconciliation incomplete. Original TN-040, complete 60-invariant registry and all 167-check evidence remain unavailable; not all 390 pages of V2 exhaustively reconciled. No new tests or changes in Phase 6D. Recommendations not authorization for protocol changes. The evidence supports coordinated hardening, not proof that wholesale redesign is necessary. Public testnet NO-GO.


---

## Preserved file: `audit/ALL_FINDINGS.md`

# WeAll Public Testnet Audit — all findings through R0

Baseline `6d3d69234415d294936d99e819367cff589ced3d` | cutoff 2026-11-20 | retrospective consolidation; no new tests or code changes.

## Executive assessment
Public participatory testnet deployment remains **NO-GO**. 81 provisional numbered findings (21 P0, 60 P1); 80 labels recovered; 8 separate tracking entries; none formally closed. The findings do not represent 81 proven production exploits. P0/P1 reflect previously reported provisional classifications; the eighth separate tracking entry is existing ADV-006, not a new numbered finding. Original full narratives were not recovered for every finding. This document restates the R0 register, not reconstructed verbatim phase transcripts.

Evidence levels: E0 hypothesis; E1 static source confirmation; E2 isolated executable reproduction; E3 production transaction-path reproduction; E4 independent multinode reproduction. Severity and evidence strength are separate. Closure objectives below are proposed, not ratified policy.

## Numbered findings — P0

### TN-001 — Unsigned seed registry
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject unauthenticated discovery records; verify independent peer discovery.

### TN-002 — Cloudflare registry verification
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify signatures and chain binding at deployed registry boundary.

### TN-003 — Observer forwarding boundary
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove observer cannot gain write or consensus authority through forwarding.

### TN-004 — Controlled-testnet mechanism gates
**P0 · OPEN · R7**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify production configuration cannot enable unsafe controlled-testnet paths.

### TN-006 — Deployment configuration
**P0 · OPEN · R7**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject unsafe or conflicting production settings before service starts.

### TN-009 — Genesis cryptographic authority
**P0 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove exact genesis authority, credential binding and expiry on independent nodes.

### TN-011 — First canonical solo finality
**P0 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify initial finality proof and transition to multi-validator epochs.

### TN-012 — Constitutional clock enforcement
**P0 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject off-slot or unauthorized time advances at build and replay boundaries.

### TN-013 — Role-dependent block replay
**P0 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify equal block replay results across node roles.

### TN-015 — Session bearer exposure in blockchain history
**P0 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Demonstrate public history contains no reusable bearer credentials.

### TN-016 — Human uniqueness and reviewer selection
**P0 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Demonstrate uniqueness constraints and authorized reviewer assignment under adversarial cases.

### TN-019 — Ballot confidentiality
**P0 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify public ledger and API cannot reveal protected voter-choice linkage under specified threat model.

### TN-020 — Automatic bans circumventing severe-sanction safeguards
**P0 · OPEN · R3**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove severe sanctions require applicable panel, appeal and enforcement authority.

### TN-021 — Public testnet governance configuration
**P0 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify enabled testnet governance conforms to authorized configuration.

### TN-022 — Proposal-defined electoral thresholds
**P0 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject thresholds outside authorized constitutional bounds.

### TN-025 — Media integrity and conflicting CID declarations
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject inconsistent commitments; verify returned bytes against expected CID.

### TN-027 — Storage capacity accounting bypass
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Enforce quotas across all admitted storage paths.

### TN-028 — Evidence deletion attestation integrity
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Require verifiable evidence deletion attestation and authorized provenance.

### TN-030 — Untrusted media MIME types
**P0 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Ensure active or unsafe media is rejected or rendered within safe isolation.

### TN-031 — Economic activation restrictions
**P0 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove economic mutations remain disabled until authorized activation conditions hold.

### TN-053 — Raw session credentials in canonical transactions
**P0 · OPEN · R2**

Evidence: E2 reported in Phase 5A history; original output and harness unavailable.

Proposed closure: Reject reusable credentials at canonical transaction and history boundaries.


## Numbered findings — P1

### TN-005 — Artifact regeneration
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Rebuild committed derivatives from clean checkout and compare digests.

### TN-007 — Frontend deployment validation
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Validate deployed build and real browser API journey at pinned revision.

### TN-008 — Independent acceptance evidence
**P1 · OPEN · R7**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Repeat fresh-clone acceptance with independent operators and retain logs.

### TN-010 — Registration resource protection
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Establish bounded unauthenticated registration and rejection without resource exhaustion.

### TN-014 — Premature procedural time progression
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify procedures cannot advance on unfinalized height.

### TN-017 — Reputation Matrix authorization discrepancy
**P1 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove reputation mutations require canonical provenance and authority.

### TN-018 — Verification status consistency
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Compare effective PoH, mirrors, eligibility transitions and snapshots across domains.

### TN-023 — Inconsistent tally criteria
**P1 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify identical outcomes across equivalent tally and resolution paths.

### TN-024 — Group membership due process
**P1 · OPEN · R3**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Ensure membership discipline requires applicable notice, review and authorization.

### TN-026 — Media replacement invalidates integrity metadata
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Ensure replacements update or invalidate metadata atomically.

### TN-029 — Incomplete storage resource isolation
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Demonstrate tenant/resource isolation under contention.

### TN-032 — Transfer identifier collision
**P1 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify domain separation, uniqueness and idempotence of transfer identifiers.

### TN-033 — Reward distribution conservation
**P1 · OPEN · R5**

Evidence: E2 reported; retrieved Phase 5B result text: R21,R22.

Proposed closure: Reject nonconserving distributions; validate scheduler provenance and atomicity.

### TN-034 — Economic readiness reporting
**P1 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject placeholder policies and incomplete activation requirements.

### TN-035 — Storage compensation settlement
**P1 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify compensation only for authorized measured settlement, exactly once.

### TN-036 — Monetary supply reconciliation
**P1 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reconcile issued supply, balances, burns if authorized, and all monetary states.

### TN-037 — Peer-store saturation
**P1 · OPEN · R6**

Evidence: E2 reported; retrieved Phase 5C result text: peer store saturation.

Proposed closure: Verify bounded peer rotation and discovery under saturated hostile fixtures.

### TN-038 — Multi-hop peer discovery failure
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Demonstrate safe discovery and synchronization beyond bootstrap peers.

### TN-039 — Peer advertisement temporal validation
**P1 · OPEN · R6**

Evidence: E2 reported; retrieved Phase 5C result text: zero start/expiry.

Proposed closure: Validate time bounds and signatures, including missing and zero values.

### TN-040 — Original description not recovered
**P1 · OPEN — evidence missing · R0**

Evidence: Identifier only; prior P1 classification inferred from counts.

Proposed closure: Recover original finding narrative and evidence; never reuse this identifier.

### TN-041 — Peer persistence failure reporting
**P1 · OPEN · R6**

Evidence: E2 reported; retrieved Phase 5C result text: persistence failure.

Proposed closure: Surface write failures without falsely reporting durability.

### TN-042 — Historical transaction visibility after checkpoint recovery
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify required historical visibility and explicit pruning behavior after recovery.

### TN-043 — Synchronization verification after durable commitment
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject unauthenticated history before durable commitment or prove safe rollback.

### TN-044 — Intergenerational historical preservation
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify required archival history survives multi-generation recovery.

### TN-045 — Incorrect recovery agreement calculation
**P1 · OPEN · R6**

Evidence: E2 reported in Phase 5A history; original output and harness unavailable.

Proposed closure: Verify agreement formula and boundary cases against authorized policy.

### TN-046 — Incomplete historical integrity verification at startup
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject or quarantine corrupted history before serving authoritative state.

### TN-047 — Helper receipt semantic verification
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject validly signed but semantically invalid helper outputs.

### TN-048 — Execution manifest authentication
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify authenticated canonical execution manifest and replay binding.

### TN-049 — Helper certificate recovery
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify restart recovery and receipt/certificate replay safety.

### TN-050 — Helper timeout enforcement
**P1 · OPEN · R1**

Evidence: E2 reported; retrieved Phase 5C result text: missing timestamp.

Proposed closure: Verify missing and boundary timestamps cannot bypass timeout policy.

### TN-051 — Inconsistent ledger references
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify canonical ledger references across execution, restart and replay.

### TN-052 — Hierarchical state conflict detection
**P1 · OPEN · R1**

Evidence: E2 reported; retrieved Phase 5C result text: hierarchical and alias overlaps.

Proposed closure: Detect normalized-path and ancestor/descendant hazards; prove serial equivalence.

### TN-054 — Device revocation leaves sessions active
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove revoked device sessions cannot authenticate after effective revocation.

### TN-055 — Unbounded session lifetime
**P1 · OPEN · R2**

Evidence: E2 reported in Phase 5A history; original output and harness unavailable.

Proposed closure: Enforce bounded expiration against canonical session policy.

### TN-056 — Recovery-induced account denial of service
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove only legitimate recovery can restrict accounts; demonstrate restoration path.

### TN-057 — Failed recovery reversal can leave account locked
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify recovery failure is atomic and restoration cannot strand accounts.

### TN-058 — Encrypted evidence intake validation
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Validate encrypted evidence structure, binding and safe failure paths.

### TN-059 — Premature PoH submission reconciliation
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Require canonical evidence and submission confirmation before completion.

### TN-060 — Incorrect reviewer-readiness representation
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Match displayed readiness to effective reviewer entitlement.

### TN-061 — Inconsistent transaction confirmation requirements
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Require consistent finality confirmation for frontend transaction lifecycles.

### TN-062 — Observer queue discards unresolved transactions
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Retain unresolved transactions or expose explicit terminal disposition.

### TN-063 — Upstream transaction rejection not reconciled
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Propagate upstream rejection and reconcile local status.

### TN-064 — Unsafe automatic retry
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify retry idempotence and ambiguity handling.

### TN-065 — Inconsistent node identity
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify canonical node identity across API, transport and persistence.

### TN-066 — Insufficient quorum bounds
**P1 · OPEN · R4**

Evidence: E2 reported; retrieved Phase 5B result text: R12.

Proposed closure: Prove authorized minimum quorum at every proposal creation and resolution boundary.

### TN-067 — Constitutional deliberation can be abbreviated
**P1 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Enforce minimum authorized deliberation windows against finalized time.

### TN-068 — Incomplete historical proposal version commitments
**P1 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Bind proposal semantics and decision evidence to immutable historical versions.

### TN-069 — Incorrect constitutional version ordering
**P1 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify canonical amendment ordering, replay and activation.

### TN-070 — Incorrect ballot-context commitments
**P1 · OPEN · R4**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Bind ballot authorization to correct election, scope, version and context.

### TN-071 — Inconsistent governance approval semantics
**P1 · OPEN · R4**

Evidence: E2 reported; retrieved Phase 5B result text: R16.

Proposed closure: Require equivalent early and deadline rules for each authorized proposal type.

### TN-072 — Multi-option expiration counting
**P1 · OPEN · R4**

Evidence: E2 reported; retrieved Phase 5B result text: R14.

Proposed closure: Verify multi-option tally and expiration semantics against authorized rules.

### TN-073 — Fraudulent storage proof
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject fabricated possession/availability proofs under specified threat model.

### TN-074 — Receipt validation
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject malformed, misbound and replayed receipts at all applicable boundaries.

### TN-075 — Reputation reversal
**P1 · OPEN · R5**

Evidence: E2 reported; retrieved Phase 5B result text: R25,R26.

Proposed closure: Demonstrate deterministic correction with saturation and intervening events.

### TN-076 — Predictable dispute panels
**P1 · OPEN · R3**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Verify selection resists applicable manipulation and conflict-of-interest threats.

### TN-077 — Unbounded rejected-certificate accounting
**P1 · OPEN · R1**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Bound rejection accounting without compromising safety or diagnostics.

### TN-078 — Local manifest precedence over canonical clock policy
**P1 · OPEN · R1**

Evidence: E2 reported; retrieved Phase 5C result text: manifest precedence.

Proposed closure: Reject conflicting configuration or enforce canonical agreement across nodes.

### TN-079 — Ambiguous account-recovery identifiers
**P1 · OPEN · R2**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Prove identity resolution is unique and unauthorized recovery cannot target aliases.

### TN-080 — Reversal requests escape expiration
**P1 · OPEN · R5**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Enforce authorized reversal deadlines and reject unauthorized late mutation.

### TN-081 — Malformed upstream confirmation acceptance
**P1 · OPEN · R6**

Evidence: Prior Phase 6D label only; original narrative and proof pending retrieval.

Proposed closure: Reject malformed, misbound or unauthenticated confirmations.

## Cross-domain and additional candidates

These remain separate from the 81 numbered entries. Possible overlaps are not adjudicated duplicates. Source observations below derive from Phases 6B–6D and the retrieved regression records. Production reachability remains unproven unless specifically stated.

### R0-C01 — Effective PoH versus legacy electorate

Canonical `effective_poh_tier()` distinguishes status and expiry; governance electorate construction reads mirrored `poh_tier` with account flags. The v1 emissary election electorate also imports this governance predicate. Expiration synchronization mitigates some cases. Existing snapshots and suspended/challenged status transitions require verification. Affected invariants were previously reported as INV-019, INV-027, INV-029; their full original definitions remain missing.

Possible overlap: TN-018; TN-021.

Source/evidence: runtime/poh/state.py#L200-L279; runtime/apply/governance.py#L647-L735; runtime/apply/groups.py#L1478-L1574.

Proposed closure: Signed status transitions and snapshot semantics; verify actual voter authorization.

### R0-C02 — Reviewer sanctions not reflected in lane eligibility

Dispute and PoH accountability set `dispute_juror_eligible` / `poh_reviewer_eligible` false; the shared lane predicate evaluates role/lane records instead. The PoH handler also writes a separate suspended-reviewers record. Need to prove whether assignment/action handlers enforce these flags independently. Legitimate suspension must be effective without involuntarily binding reviewers to service.

Possible overlap: TN-017; TN-020.

Source/evidence: runtime/reviewer_responsibilities.py#L164-L198; runtime/apply/dispute.py#L3342-L3398; runtime/apply/poh.py#L2220-L2280.

Proposed closure: Apply legitimate accountability action and verify subsequent assignment and vote authorization.

### R0-C03 — Dispute quorum contraction

V1 dynamic quorum can contract with the eligible reviewer population. V2 initial-panel protection preserves the original threshold and checks panel completeness; source notes no current governance activation path. Seven original jurors have an illustrative 5-vote threshold; loss of eligible reviewers can reduce the V1 threshold. Do not infer verdict approval from quorum alone. Verify appeal/replacement transitions separately; never activate the dormant policy as an audit action.

Possible overlap: TN-020; TN-076.

Source/evidence: runtime/apply/dispute.py#L837-L983.

Proposed closure: Compare v1 and v2 for withdrawal, replacement, incomplete panels, and resolution; no policy activation implied.

### R0-C04 — Emissary seating eligibility and treasury availability

Election creation normalizes candidate IDs, and finalization evaluates valid ballots and versioned quorum, calculates STV winners and updates emissaries and group/treasury signers. No independent candidate eligibility check was located in these handlers. Finalization also fills fewer than five winners from remaining candidates. Downstream signer checks may prevent spending while leaving signer threshold unavailable. Need to establish valid membership, account and eligibility requirements at authorized lifecycle points.

Possible overlap: TN-021; TN-024.

Source/evidence: runtime/apply/groups.py#L1478-L1574; runtime/apply/groups.py#L1755-L1947.

Proposed closure: Verify eligible candidates at authorized lifecycle points; verify valid signer threshold after seating.

### R0-C05 — Account recovery across institutional authority

Recovery revokes prior signing keys, devices and sessions, installs new credentials and increments authority generation. Validator keys, operator responsibilities, reviewer assignments and treasury obligations can have separate lifecycles; automatic removal could undermine consensus availability. Verify each transition and the applicable recovery/continuity policy.

Possible overlap: TN-054; TN-056; TN-057.

Source/evidence: runtime/apply/identity.py#L1258-L1367.

Proposed closure: Verify role-specific transitions and quorum availability, not unconditional role revocation.

### R0-C06 — Stale same-block authority

Block admission adjusts signer nonce but does not visibly reconstruct all preceding authority mutations. The dispatcher rechecks founder expiry and recovery restrictions, so this is not a total absence of apply-time gates. A revoked-key transaction following a revocation in the same block requires signed reproduction and an explicit effective-point rule (transaction order or next block boundary).

Possible overlap: TN-009; TN-013.

Source/evidence: runtime/block_admission.py#L323-L477; runtime/block_replay.py#L690-L770; runtime/apply/identity.py#L547-L591.

Proposed closure: Establish authorized effective boundary and verify signed ordering, leader/follower/helper outcomes.

### R0-C07 — Explicit zero finality falls back to optimistic height

`procedure_height()` accepts positive finalized heights; explicit zero falls back to optimistic height. Phase 5C reported both direct and nested explicit-zero assertion failures (actual 3 instead of 0). Confirm scheduler reachability and preserve genuinely absent-field legacy behavior.

Possible overlap: TN-014; TN-012.

Source/evidence: runtime/constitutional_clock.py#L172-L191.

Proposed closure: Verify explicit zero versus absent finality at procedure and production scheduler boundaries.

### ADV-006 — Placeholder economic policy readiness

Phase 5B R18 reported placeholder policy records producing ready=True; empty state is rejected. This is a predicate failure, not proof that an unauthorized production activation succeeds.

Possible overlap: TN-031; TN-034.

Source/evidence: Phase 5B R18.

Proposed closure: Verify readiness rejects incomplete policies; prove activation path fails closed.

## Recovered experimental observations

The preserved Phase 5B and 5C logs describe source-excerpt/predicate fixtures. The results below were not rerun for this archive. An illustrative assertion must be checked against authorized policy before being treated as a defect.

| Finding | Expected / observed |
|---|---|
| TN-033 | Balanced distribution preserves aggregate 100; debit 50 with credit 40 or 0 accepted and leaves 90 or 50. Production scheduler reachability not proven. |
| TN-037 | Saturated 64-peer store did not admit new peer. Network-wide eclipse not demonstrated. |
| TN-039 | Signed-record fixtures with zero start or expiry accepted. Signature verification was fixture-based. |
| TN-041 | Peer persistence failure not surfaced. |
| TN-050 | Missing timestamp left a helper request window open. |
| TN-052 | Parent/child read-write and write-write conflicts, and slash aliases, were not caught. Opposite writes in the diagnostic gave balances 20 and 10. This is not a proven production merge-order divergence. |
| TN-066 | Quorum 1 observed for a synthetic 10,000-member electorate with 1 basis point; illustrative floor 6,700 is not a newly authorized threshold. |
| TN-071 | Same illustrative tally returned early=False, deadline=True. |
| TN-072 | Multi-option total 80 yielded counted=0 in the inspected direct-only counting function. |
| TN-075 | Initial ±95,000 saturates at ±100,000 after ±20,000 delta, then reverses to ±80,000 rather than original value. |
| TN-078 | Synthetic manifest interval 30,000 overrides committed 20,000; committed slot rejected. Conflicting live-node configuration reachability not established. |
| ADV-006 | Placeholder policy returns ready=True. |
| R0-C07 | Direct and nested zero finalized height return optimistic height 3. |

Positive controls include balanced distribution, rejection of over-credit and overdraw fixtures, maximum issuance cap, duplicate issuance-epoch handling, ordinary peer time/signature controls and off-slot clock rejection. The 5/5 issuance model assumes eligible epochs settle and does not verify actual runtime issuance.

## Remediation and release policy

R0 preserve evidence; R1 consensus foundation; R2 identity and authority; R3 constitutional justice; R4 democratic governance; R5 reputation and economics; R6 infrastructure and product; R7 independent revalidation. Proposed first R1 targets: TN-052, TN-078, R0-C07 and R0-C06. Preserve current behavior before modifying it. All findings require independent validation; a passing CI suite or dormant stronger implementation does not in itself close a defect. Consult the R0 closure contract.

Proposed composite release gates: canonical finality; deterministic execution/replay; credentials; human uniqueness; reputation correction; justice/appeals; governance/ballots; treasury/economic isolation; private evidence/media security; peer discovery; persistence/recovery; helper/serial equivalence; frontend acceptance; independent adversarial review; reproducible deployment and authorization. No composite gate was formally cleared by this audit.

## Related browser acceptance finding (not part of TN register)

F-002 — `invalid_poh_journal_entry` during asynchronous PoH evidence submission. Earlier acceptance report describes same-origin proxy configuration as an empty node address rejected by the journal before upload. Clean install, README verification and observer frontend access passed; recording/review reached; encrypted submission failed. Exact baseline and current resolution not independently established in this archive. Keep separate from 81 TN entries; evaluate possible overlap with TN-058 and TN-059 only after source evidence is recovered. This contextual observation does not establish IPFS or blockchain failure.

## Limitations

Original TN-040 description, complete INV-001–INV-060 text, original full numbered narratives and proof records, original harnesses and remaining test records could not be recovered. Prior R0 phase allocations/acceptance objectives are proposals. Public testnet verdict remains NO-GO.


---

## Preserved file: `audit/EVIDENCE_INDEX.md`

# Evidence and reconciliation index

Frozen baseline `6d3d69234415d294936d99e819367cff589ced3d`.

## Bundled evidence
| Artifact | Scope | Provenance |
|---|---|---|
| r0/master_register.tsv | 81 IDs | Prior R0, labels and proposed closure objectives |
| r0/candidate_register.tsv | 8 entries | Prior R0, possible overlaps and locators |
| r0/evidence/phase5b_retrieved_result.txt | 22 source checks (14 pass, 8 fail), separate 5 model pass | Retrieved text, original `weall_phase5b_results.txt` |
| r0/evidence/phase5c_retrieved_result.txt | 31 checks (19 pass, 12 fail) | Retrieved text, original `weall_phase5c_results.txt` |

## Prior reports, not raw evidence
- Phase 5A: 10 checks, 6 pass/4 fail (historical report only).
- Phase 5F: earlier conversation retrieval reports 30 checks, 28 pass/2 fail and TN-031 reproduced; original output and harness not recovered. Treat as unverified historical metadata, not a new reproduction or an evidence-level upgrade.
- Cumulative: 167 checks, 119 pass/48 fail, historically reported. Do not sum these subtotals into the cumulative count or assume the separate mathematical model is included. The records do not completely reconcile the total.
- Phase 6B: six cross-domain candidate descriptions, with exact-baseline source locators. Phase 6C: proposed consolidation into ten families; no formal merges or downgrades. Phase 6D: 80 labels recovered, TN-040 reserved. R0: 81 entries and eight separate tracked entries preserved.

## Source links cited in earlier audit
These links reference the frozen revision. They are indexed for follow-up rather than fresh source verification in this packaging turn.
- [net/gossip.py#L274-L331](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/gossip.py#L274-L331)
- [net/peer_list_store.py#L1-L141](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/peer_list_store.py#L1-L141)
- [runtime/apply/dispute.py#L3342-L3398](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/dispute.py#L3342-L3398)
- [runtime/apply/dispute.py#L837-L983](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/dispute.py#L837-L983)
- [runtime/apply/governance.py#L647-L735](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/governance.py#L647-L735)
- [runtime/apply/groups.py#L1478-L1574](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/groups.py#L1478-L1574)
- [runtime/apply/groups.py#L1755-L1947](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/groups.py#L1755-L1947)
- [runtime/apply/identity.py#L1258-L1367](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/identity.py#L1258-L1367)
- [runtime/apply/identity.py#L547-L591](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/identity.py#L547-L591)
- [runtime/apply/poh.py#L2220-L2280](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/poh.py#L2220-L2280)
- [runtime/block_admission.py#L323-L477](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/block_admission.py#L323-L477)
- [runtime/block_replay.py#L690-L770](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/block_replay.py#L690-L770)
- [runtime/block_time_admission.py#L116-L197](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/block_time_admission.py#L116-L197)
- [runtime/block_time_admission.py#L72-L113](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/block_time_admission.py#L72-L113)
- [runtime/constitutional_clock.py#L172-L191](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/constitutional_clock.py#L172-L191)
- [runtime/domain_apply.py](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/domain_apply.py)
- [runtime/domain_dispatch.py](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/domain_dispatch.py)
- [runtime/helper_dispatch.py#L298-L322](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/helper_dispatch.py#L298-L322)
- [runtime/helper_merge.py#L243-L277](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/helper_merge.py#L243-L277)
- [runtime/helper_merge.py#L63-L75](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/helper_merge.py#L63-L75)
- [runtime/poh/state.py#L200-L279](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/poh/state.py#L200-L279)
- [runtime/reviewer_responsibilities.py#L164-L198](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/reviewer_responsibilities.py#L164-L198)
- [runtime/runtime_context.py](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/runtime_context.py)

## Missing evidence and controls
- Original TN-040 title and evidence; do not assign this ID anew.
- Complete original 60-invariant registry; references to selected invariant IDs cannot substitute for full definitions.
- Original Phase 1–6 narrative records and complete 167-check logs; exact traceability for every TN ID is incomplete.
- Original Python harnesses `weall_phase5b_regressions.py` and `weall_phase5c_regressions.py`: indexed records located but export unavailable. Do not label the transcript text as runnable code or original file bytes.
- Production reachability, policy authorization and independent multinode validation remain open where specified. Preserve actual results, source hashes and environment metadata before closing.
- Archive SHA-256 hashes certify bundled bytes, not provenance or runtime correctness. Original R0 content retained under r0/ with its original checksums.


---

## Preserved file: `audit/r0/README.md`

# WeAll R0 — remediation evidence preservation

Baseline: `6d3d69234415d294936d99e819367cff589ced3d` ([commit](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d)).

Status: **R0 partial; public participatory testnet NO-GO.** No repository edits, commits, policy activation, or new production tests. This package is a local chat deliverable, not a repository artifact.

## Contents

- `master_register.tsv`: all 81 identifiers, prior Phase 6D labels, prior provisional severities, proposed remediation phase and individual acceptance objectives. 80 descriptions are carried forward, not independently recovered original narratives; TN-040 remains reserved.
- `candidate_register.tsv`: 8 separate tracking entries, including six Phase 6B candidates, zero-finality candidate and existing ADV-006 label. Possible overlaps are hypotheses, not merges.
- `evidence/`: retrieved-text transcriptions from `weall_phase5b_results.txt` and `weall_phase5c_results.txt`, not raw source archives. Hashes certify bundled bytes only. The originals and both Python harness files were located but could not be exported.
- `SHA256SUMS`: digest of each bundled payload (no claim of matching original file hash).

## Proposed primary phase allocation

| Phase | Findings | Scope |
|---|---:|---|
| R0 | 1 | Evidence recovery |
| R1 | 14 | Consensus foundation |
| R2 | 13 | Identity and authority |
| R3 | 3 | Constitutional justice |
| R4 | 11 | Democratic governance |
| R5 | 9 | Reputation and economics |
| R6 | 27 | Infrastructure and product |
| R7 | 3 | Independent revalidation |

All findings require R7 independent revalidation regardless of primary phase. Ordering does not authorize changes to constitutional policy.

## Evidence accounting

| Record | Checks | Passed | Failed | Status |
|---|---:|---:|---:|---|
| Phase 5A | 10 | 6 | 4 | Historical report only; original records unavailable |
| Phase 5B source checks | 22 | 14 | 8 | Retrieved result text, not rerun |
| Phase 5C source checks | 31 | 19 | 12 | Retrieved result text, not rerun |
| Phase 5B mathematical model | 5 | 5 | 0 | Retrieved result text; separate scope |
| Cumulative prior report | 167 | 119 | 48 | Unreconciled; do not add above rows again |

E0 hypothesis; E1 source confirmed; E2 isolated executable check; E3 signed production transaction-path reproduction; E4 independent multinode reproduction. The E2 designations in the register mean previously reported evidence, not fresh independent reproduction. Failure against a synthetic assertion may require adjudicating whether the assertion matches authorized policy.

## Closure contract

For every ID preserve baseline commit, original prose and source lines, affected invariants, actual effective deployment profile, reproduction command and dependencies, expected and actual results, patch commit, negative and positive regression results, evidence of deterministic replay where applicable, exact-head CI and independent production acceptance. Any P0/P1 severity change must record rationale and review. Duplicate findings retain original IDs and closure evidence. A dormant defect can be classified as unreachable only with enforceable profile gates and tests. No vulnerability closure is claimed.

## Missing records

Recover original TN-040, the original 60-invariant registry at this exact baseline (older registries are not substitutes), original 81 finding narratives/proofs, complete original 167-check evidence, raw Phase 5A/B/C outputs and harnesses, and other prior experimental artifacts. Do not infer missing invariant texts or counts. Preserve original artifacts byte-for-byte with SHA-256 once available.

## R1 intake

Begin verification of TN-052, TN-078, R0-C07 and R0-C06 using signed production-path tests at the frozen baseline; preserve original behavior before a patch. Verify canonical authority-effective-point policy before changing authorization. Expand to other R1 entries; no code change is authorized by this package.


---

## Preserved file: `remediation/weall_r1a/README.md`

# R1A — TN-052 hierarchical helper conflicts

Baseline: `6d3d69234415d294936d99e819367cff589ced3d`.
Status: **candidate patch prepared; isolated validation passed; production validation and closure pending**.

## Source and scope

The pinned `Weall-Protocol/src/weall/runtime/helper_merge.py` (Git blob `176ac7c6dd37beccf30f78290a681897bc06079b`) compares exact access strings at lines 243–263, but `_set_path` and `_delete_path` interpret slash-delimited components and ignore empty segments. The merge already returns the untouched base state and serializes all expected lanes when overlap is detected. The patch changes only conflict detection: exact/ancestor/descendant relationships, slash aliases, actual delta paths, and deterministic lane traversal. It preserves case, treats colon as an ordinary component character, does not mutate certificate/hash encodings, and uses the existing fallback. Comparing actual and declared write paths conservatively can serialize otherwise independent lanes. The prefix index avoids all-pairs comparisons, but pathological depth/input-size resource bounds have not been measured.

Source: https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/helper_merge.py#L243-L277

The pinned existing test module blob is `3ca814736bf4cd95fc1fb0ccf0872a53c884396f`. The installer verifies both files against their Git blob identifiers before writing. Apply to a clean dedicated branch, not to a running deployment. This is not a protocol activation or a consensus compatibility authorization. Historical replay and mixed-version compatibility require review before a network upgrade.

## Apply and validate

From the repository root, with the ZIP extracted outside or inside the checkout:

```sh
git status --short
git switch -c remediation/r1a-tn052
python /path/to/weall_r1a/apply_r1a.py "$PWD"
git diff --check
git status --short
cd Weall-Protocol
PYTHONPATH=src python -m pytest -q tests/test_helper_merge.py tests/test_tn052_hierarchical_conflicts.py tests/test_helper_materialized_merge_restart.py
```

Use the project's established Python environment and dependencies. The installer declines modified/nonmatching source blobs or an existing new test file, and invokes `git apply --check` first. Review the diff and appended test before committing. The installer does not commit or push. The integration regression uses the repository's existing certificate fixtures (not authenticated live helpers). If an installation step fails after the patch has been applied, inspect the working tree before retrying.

## Evidence

- Baseline isolated detector: 7 passed, 10 failed.
- Proposed isolated detector: 17 passed, 0 failed.
- Proposed detector: 400 reference comparisons across pairs of ten path strings and read/write modes, with both input permutations checked per comparison.
- Patch context/syntax checked against a reconstructed source excerpt, not a full Git checkout.
- The original and modified detector excerpts are supplied as `.py.txt`; they are not complete production modules. `run_isolated.py` uses minimal stand-in lane and delta types and imports neither real certificates nor production execution. Re-run using `python run_isolated.py before` (expected nonzero) or `python run_isolated.py after` (expected zero), with pytest installed.
- Full production tests were not executed: direct Git network access from the execution environment could not resolve github.com; source was read through an authenticated repository connector. The proposed integration test is unexecuted.

## Required next evidence

1. Verify the original integration regression fails on the pinned baseline and passes with the candidate; verify the positive disjoint-lane cases, hash commitments and restart tests.
2. Investigate the planner's separate exact-string `_access_conflicts` predicate in `parallel_execution.py` and any earlier or alternative conflict checks. This patch addresses the final materialized merge detector, not every planner/executor path.
3. Confirm that real signed helpers cannot bypass the fallback, that missing/invalid lanes cannot create conflicting partial execution, and that the caller executes the correct canonical serial transaction order. Exercise namespace-relative vs legacy mapping, same-lane duplicate/overlapping delta paths, implicit parent creation and state-shape invariants. These related concerns are not closed by this patch.
4. Compare full state roots, receipts, transaction order and replay outcomes under serial execution, helper success, helper conflict/fallback, timeout and restart; execute independently on multiple nodes.
5. Run exact-head CI, review migration/replay safety and record the patch commit and independent acceptance. Keep TN-052 OPEN until the R0 closure contract is satisfied. No other finding is changed.


---

## Preserved file: `supplement/RECOVERED_PHASE_RECORDS.md`

# Recovered phase records — November 20, 2026

Baseline: `6d3d69234415d294936d99e819367cff589ced3d`.

These records are **history retrieval summaries**, not verbatim chat transcripts. They supplement the earlier expanded archive; they do not replace previous source artifacts. No new executable tests were conducted. All timestamps below are UTC. Unavailable wording, individual test identities and source citations remain unavailable, rather than being inferred.

## Phase 0 and Phase 1

Original audit conversation identified by the history service as “WeAll Public Testnet Audit” / “WeAll Public Testnet Readiness Audit.” Initial report Nov 19 21:28:53; later Phase 1A–F report material around 21:47:09. Previously recovered Phase 0 index: 2,873 tracked files; 236 transaction types; 295 backend files; 1,170 tests; 143 frontend files; 125 deployment/release files. Phase 0–1F summaries remain in `audit/EARLY_PHASES_RECOVERED_HISTORY.md`.

### Phase 1G — peer networking, distributed synchronization and node security

Original numbered report located in history at Nov 19 23:16:05. Recovered titles: TN-037 Peer discovery saturation; TN-038 Multi-hop peer discovery failure; TN-039 Peer-address expiration; TN-040 Network-loop resource exhaustion; TN-041 Silent peer persistence failures. These titles are retrieved history summaries and may differ in punctuation from the original. TN-040's mechanism is documented separately and newly checked against pinned source in `TN-040.md`.

## Phase 2 — invariant extraction

Original report located at Nov 20 01:30:22. The twelve families and identifier ranges are recovered in `invariant_family_index.tsv`. All sixty were provisional verification targets, not canonical transaction IDs and not individually cleared. The original 60 invariant sentences and corresponding source mappings did not return in the history query.

## Phases 3 and 4

Adversarial and divergence analysis were previously reported, but searches did not recover the original scenario catalog, per-scenario identifiers, complete traces or full report prose. ADV-006 is referenced by the preserved Phase 5B log. Do not treat earlier October audits as equivalent to this exact November revision.

## Phase 5 — experimental reproduction

Counts are reconciled in `phase5_accounting.tsv`. This accounting is based on two directly retrieved result texts (5B, 5C) and four retrieved historical summaries (5A, 5D, 5E, 5F). The 5B mathematical model's five passing checks are separate from the 167 reported source/fixture checks. 53 individual check outcomes are available in the two stored logs; detailed individual outcomes for the remaining 114 are not available. Not all checks used real production dependencies. None of these counts establish a number of production exploits.

### Phase 5A

10 checks; six pass, four fail. The original check-by-check R01–R10 result text, harness and individual TN mapping remain unavailable. These totals were historically reported in the R0 discussion, not directly observed here.

### Phase 5B and 5C

Original result texts and text-extracted harnesses are preserved in `audit/r0/evidence/` and `harnesses/` respectively. Phase 5B: 22 source-level checks (14 pass, 8 fail), plus five separate mathematical model checks. Phase 5C: 31 checks (19 pass, 12 fail). Original raw harness bytes were not recovered. No reruns in this preservation turn.

### Phase 5D — recovered historical report details

Original report timestamp: Nov 20 03:59:38. 32 checks (24 pass, 8 fail). Referenced findings TN-057, TN-079 and TN-080. Reviewer-independence controls 13/13 passed. Reported method: five checksum-matched source excerpts and synthetic fixtures. Production reachability, human uniqueness and end-to-end dispute adjudication unverified. Individual check identities and outputs not recovered; the 13 controls are reported within the phase, not added to counts.

### Phase 5E — recovered historical report details

Original report timestamp: Nov 20 16:24:45. 42 checks (28 pass, 14 fail). Referenced findings TN-061, TN-060, TN-065, TN-062, TN-003, TN-081, TN-058, TN-025 and TN-030. Evidence upload controls 6/7 passed. Synthetic isolated testing; browser journey, deletion, interrupted recovery and deployment boundaries remained unverified. Individual outcomes and raw harness not recovered.

### Phase 5F — recovered historical report details

Original report timestamp: Nov 20 16:38:16. 30 checks (28 pass, 2 fail). TN-031 reportedly reproduced at predicate level: public-testnet economic lock fails after unlock with economics enabled. SYSTEM binding controls reportedly 10/10 passed; bindings included queue ID, type, height, phase, signer, parent and payload hash. Follower checks required SYSTEM ordering/presence. Trusted-anchor comparisons reportedly six passes and reject mismatched roots/finalized identifiers; synchronization applies blocks before terminal anchor validation (TN-043 concern from earlier archive). These are in-memory synthetic fixtures; no production exploit, unauthorized issuance or conflicting finality demonstrated. Individual failed check descriptions and original logs not recovered.

## Phase 6A — reverse authority tracing

Historical report located Nov 20 16:44:31. The available history summary identifies TN-020 automatic reputation-floor bans potentially bypassing severe-sanction safeguards (P0, reported INV-023/025/028/033 links); legacy identity ACCOUNT_BAN bypass not canonically routed; dispute inline account/eligibility mutations differing from ordinary handlers; TN-071 governance execution trusting scheduler-supplied approval fields; slashing proposal/vote overwrite and threshold-reconstruction concerns remained provisional. This is an incomplete summary, not the original execution trace, and not a new source-level verification.

## Phase 6B, 6C, 6D, R0, R1A

Earlier archive reports and candidate patch are unchanged. R1A remains uncommitted and independently unvalidated at full production path. No finding is formally closed by this supplemental preservation work.


---

## Preserved file: `supplement/TN-040.md`

# TN-040 — Network-loop resource exhaustion

Prior provisional severity: P1 (preserved). Status: OPEN. No change to repository or runtime. Baseline: `6d3d69234415d294936d99e819367cff589ced3d`.

## Historical recovery

Phase 1G report at Nov 19 2026 23:16:05 UTC: the history retrieval returns the title “Network-loop resource exhaustion” and the mechanism that synchronous HTTP requests during seed discovery share the network loop, while the response reader lacks an explicit size limit. Potential impacts include latency or disruption to transaction propagation, consensus delivery, peer discovery and node responsiveness, plus memory pressure. This is a recovered summary, not a verbatim original report.

## Newly rechecked source evidence (static only)

`Weall-Protocol/src/weall/net/net_loop.py`, pinned Git blob `fc0427bdf4d7ba727d821563593e57eb466770c4`.

- [`_http_get_json()`, lines 256–277](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/net_loop.py#L256-L277): synchronous `urllib.request.urlopen(req, timeout=float(timeout_s))`, followed by unbounded `data = resp.read()` before decoding JSON. A socket timeout is configured but the read has no explicit byte budget. Source excerpt was fetched through GitHub at the exact SHA; the file is not represented as a standalone original attachment here.
- [`_seed_discover_once()`, lines 711–757](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/net_loop.py#L711-L757): loops through configured seeds and directly invokes `_http_get_json()` for each seed.
- [`_seed_discovery_tick()`, lines 757–764](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/net_loop.py#L757-L764): periodic refresh invokes `_seed_discover_once(force=True)` synchronously when enabled and due.
- [`_run()`, lines 903–925](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/net_loop.py#L903-L925): invokes `_seed_discovery_tick()` inside the loop that also polls the node.
- [`Startup`, lines 789–815](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/net/net_loop.py#L789-L815): initial discovery also executes before the network thread starts.

## Proposed acceptance objective (new recommendation, not original report wording)

Bound response bytes, total request deadline, concurrency and aggregate refresh work; ensure slow, oversized or unresponsive configured seeds cannot prevent unrelated network processing. Add local synthetic-server and controlled multinode regression coverage proving bounded memory and continued processing, including refresh disabled/enabled paths. Preserve authenticated peer handling and existing fail-closed behavior. No patch, no exploit reproduction or deployment reachability finding was established in this turn. E1 static confirmation only.


---

## Preserved file: `reaudit/REAUDIT_REPORT.md`

# WeAll public testnet audit — source re-audit supplement

**Baseline:** `6d3d69234415d294936d99e819367cff589ced3d`  
**Date:** 2026-11-20  
**Mode:** read-only repository inspection and offline executable diagnostics. No repository mutation, release authorization, implementation change or formal finding closure.

## 1. Purpose and evidence boundaries

The original audit reports 81 numbered findings, 60 provisional invariants, and 167 source/fixture checks (119 pass, 48 fail). The earlier archive preserves 53 individual outcomes and two text-extracted diagnostic harnesses. The remaining original 114 individual check records and historical invariant wording cannot be recovered verbatim. The owner has authorized fresh source re-audit instead of waiting for exported chat history. This supplement is a replacement evidence layer, not a purported recovery of the missing original messages.

All new source excerpts were requested through the repository connection at the frozen commit, not the mutable default branch. Each executable excerpt was independently checked against its FNV-1a checksum computed from a separate pinned source retrieval. The manifests also record Git blob identifiers returned by GitHub. These are excerpt identity checks, not a cryptographic proof of the entire source tree. The full checkout was unavailable because the execution container could not resolve github.com. Neither this report nor any PASS row proves complete production integration, real cryptographic authorization, browser acceptance, persistent state installation or independent-node agreement. Test dependencies are explicitly substituted in the harnesses. No live node, private identity, real bearer secret, or external storage provider was used.

The recovered Phase 5B and 5C text harnesses were executed as Python; both completed with the same historical counts. Their exit code 1 means a found invariant failure, not a failure to execute. The five issuance-model checks are separately tracked. No original record has been rewritten. A failure is a difference from an explicit test expectation, and does not by itself prove a public exploit. Some expectations are proposed safety properties that require policy adjudication. In the replacement invariant registry, CONTROL_PASS means scoped evidence for a predicate, not a production acceptance clearance; CONDITIONAL_FAIL denotes an observed failure under assumptions requiring verification; FAILING_EXCERPT denotes a directly isolated discrepancy; OPEN means the broader requirement is not established. Reconstructed `REINV-*` identifiers are deliberately distinct from historical `INV-*` identifiers. Associations are by family, not a claim that historical individual definitions have been reconstructed exactly.

## 2. Phase 0 refresh: transaction canon and source map

The pinned `Weall-Protocol/generated/tx_index.json` Git blob `f9b521af1fe1a4ca0613b0c955399d119efb73cf` contains 236 transaction types, 236 unique names and 236 unique `id` values. The `by_name` index resolves each name to its position in `tx_types`. The `by_id` index uses numeric keys; the transaction objects carry hexadecimal strings. The by-name linkage passed the inspected comparison. No assertion about numeric alias semantics or index corruption is made without inspecting the index loader and historical compatibility contract. Metadata declares version 1.25.0, append-only law and transaction canon v1.22.2. Its source digest is `d68ee9574c4a9672fe0aacf34eb5bb996138594bbbe26b952f783711dac87d12`.

The committed `audit-metadata/GIT_TRACKED_FILES.txt` in the same revision is a historical manifest, not proof of current file-tree coverage. It listed 2,314 paths, including 280 backend source paths, 995 test paths and 109 `web/src` paths. This differs from the previously reported live audit counts; do not infer that files were removed. A fresh `git ls-tree` could not be run. The generated V2 parameter registry at Git blob `3ab4b73a3b51a37226c494b5692b0e8c15865632` has 215 rows; its presence is not evidence of constitutional activation.

The refreshed module map covers transaction/block admission (`runtime/block_admission.py`), replay (`runtime/block_replay.py`), SYSTEM scheduling and validation (`runtime/system_tx_engine.py`), role and human-status predicates (`runtime/poh/state.py`, `runtime/reviewer_responsibilities.py`), identity/recovery (`runtime/apply/identity.py`, `runtime/recovery_review.py`, `runtime/account_recovery_scheduler.py`), civic eligibility (`runtime/apply/governance.py`), procedure clocks (`runtime/constitutional_clock.py`, `runtime/block_time_admission.py`), economics (`runtime/econ_phase.py`), helper merge (`runtime/helper_merge.py`), sync (`net/state_sync.py`), API session/observer/evidence surfaces (`api/security.py`, `api/routes_public_parts/tx.py`, `api/routes_public_parts/poh.py`), and the retrieved historical peer, governance, economic and helper excerpts. This is targeted indexing; not a fresh exhaustive transaction-to-handler mapping for all 236 types.

## 3. Phase 1 refresh: relevant execution traces

### Account session lifecycle (TN-015/053/054/055)

`_apply_account_session_key_issue` (`runtime/apply/identity.py:687–745`) extracts a bearer string from the envelope, derives a TTL from `ttl_s` or an expiry timestamp, and caps/defaults the TTL only if an account-owned positive session TTL is present. It calls `store_session_record` (`runtime/session_keys.py:50–56`), which stores the hash and format metadata rather than the bearer as a new account-state key. `require_account_session` (`api/security.py:139–181`) resolves the hashed record (with historical raw-key lookup fallback), checks `active is True`, then checks ledger-clock expiration only if TTL is positive. `ACCOUNT_DEVICE_REVOKE` modifies the device row and account nonce; the inspected private API gate does not read device status. `ACCOUNT_SESSION_KEY_REVOKE` separately resolves and marks the session inactive. The full canonical block persistence path for the raw input was not exercised. The stronger historical raw-bearer-history claim remains unclosed.

### Recovery lookup and lifecycle (TN-057/079/080)

`_iter_recovery_requests` traverses accounts and each recovery request mapping; `_find_recovery_request` returns the first matching request ID. `schedule_account_recovery_system_txs` iterates sorted accounts/requests, expires continuity awaiting social attestations, assigns continuity/reversal panels, and resolves under-review requests using approval/rejection thresholds and review deadline. It enqueues SYSTEM finalization or receipt work. `_apply_account_recovery_receipt` then records failures, closes evidence, clears the lock for non-reversal methods, and clears the active reversal request for reversal methods without explicitly clearing `account.locked`. The recovery-open path (identity.py:1914–1989) writes `active_reversal_request_id`, extends restrictions and sets the subject locked. Whether the awaiting-social reversal state can occur with accepted input and whether another authorized unlock route is guaranteed remain open.

### Observer queue and confirmation (TN-062/081)

`_prune_tx_queue_rows` filters expirations, retains old accepted entries under the TTL rule, sorts by age and truncates to the record limit. Only afterward does its byte-budget stage prefer confirmed records for eviction. Under an unresolved-only byte load it drops unresolved records. `_status_from_upstream` reads at most 1 MiB, parses a dictionary, rejects a provided mismatching transaction ID, and coerces the `ok` field by truthiness. It does not itself require a returned transaction ID, committed height or successful receipt. The separate `_prove_already_applied_tx_at_matching_tip` boundary (tx.py:1362–1468) requires a matching ID, confirmed status, `apply_ok is True`, local height/block identity, matching queue confirmation and stable local/remote current commitments. Consequently a permissive parser is not proof of false finality: each caller must be traced before escalation.

### Economic lock and SYSTEM binding (TN-031)

`is_econ_unlocked` calculates eligibility from stored unlock time (or genesis + 90 days) and compares canonical time. `_economics_enabled` coerces the state flag to a bool. `econ_allowed_from_state` combines these conditions. `deny_if_econ_disabled` allows the activation operation after unlock and rejects normal economic operations until enablement. No chain profile check is present in this primitive. Thus profile restrictions must be enforced upstream or downstream by independently authoritative policy. The predicate tests use a synthetic `network_mode` marker; they do not establish the production profile schema or an approved activation path.

`validate_system_tx_queue_binding` requires a queue ID, finds the deterministic entry, checks type, calls single-transaction lineage validation, checks due height, payload due height and phase, and compares signer, parent and canonical payload hash; emitted height must be unset, zero or current. Tests passed these comparison controls with fixture queue and lineage dependencies. The emitter and full signed block verification are not replaced by those stubs. `StateSync._anchor_matches` compares only explicitly populated trusted fields; `verify_response` separately checks header type, chain ID, schema and transaction index, required anchor presence, and snapshot commitment/semantic consistency. The terminal anchor check relative to actual block installation (historical TN-043) is still open.

### Evidence intake (TN-025/058)

`_upload_poh_video_evidence` (`api/routes_public_parts/poh.py:154–252`) applies endpoint enablement and a session principal gate, checks the declared AES-256-GCM algorithm and commitment shape, permits ciphertext MIME types, reads at most configured size + 1, verifies the exact SHA-256 commitment, and sends bytes to a controlled local store or IPFS. It validates the returned CID and reports the provider-returned size. The two negative trust-boundary probes deliberately substitute the provider, principal and CID validation. The route does not prove bytes are authentic AES-GCM ciphertext merely from a header and hash (such a proof is generally unavailable without decryption authority or additional mechanism). Whether raw arbitrary bytes are prohibited by the authorized privacy model and whether provider size must equal payload byte length for the specific IPFS codec are questions, not proven vulnerabilities. TN-025 historically concerns CID/digest declarations; the size probe is adjacent evidence, not the exact original exploit.

## 4. Phase 2 replacement registry

`INVARIANTS.tsv` defines 60 fresh verification targets across the original twelve family counts: consensus (6), deterministic execution (6), authorization (5), identity (5), reputation (5), governance (6), monetary policy (7), helper execution (8), cryptography/privacy (3), persistence (3), networking (3), frontend/API (3). Sources and status are recorded individually. Some rows rely on retained historical source locators and remain OPEN rather than falsely asserting new source verification. The file is an actionable replacement registry, not the lost original individual sentences. It may be used for future remediation after review.

## 5. Phase 3 and 4 replacement scenario analysis

| Scenario | Observed result | Boundary still required |
|---|---|---|
| Duplicate recovery request coordinates | First matching account changes when insertion order reverses (RA-025/026). | Prove duplicate request IDs can be created through admitted transactions; check canonical state serialization and iteration ordering. |
| Unresolved observer work under capacity pressure | New confirmed records displace an older accepted record; accepted-only byte pressure drops older accepted record (RA-034/036). | Rehearse durable client retry/recovery and nonce semantics under actual process and disk limits. |
| Malformed confirmation from upstream | Parser accepts missing ID/receipt or truthy string false (RA-041–043). | Inspect every caller and prove whether an invalid authoritative final status or state import is reachable. |
| Expired or omitted session TTL | Zero-TTL record remains usable at later time; issuance with no policy returns zero (RA-090/093). | Determine permitted session lifetime policy, fully admitted issuance and bypass resistance. |
| Device revoked while session remains active | Synthetic linked session retains access (RA-094); explicit session revoke works (RA-095). | Verify authoritative linkage and device revocation semantics. |
| Reversal request held pending | Awaiting-social reversal has no expiry in tested scheduler branch (RA-097). Failed/expired reversal receipt leaves initially locked account locked (RA-105/106). | Reachability of that state and constitutional lock policy/alternative recovery paths. |
| Local profile restrictions differ | Economic predicate returns true after unlock if enabled with synthetic public-testnet marker, and truthy malformed flag (RA-052/053/058). | Actual profile and policy activation path; reject incompatible typed state and test production route. |
| Hierarchical state overlap | Earlier 5C rerun reproduces ancestor/descendant and alias conflicts missed by exact comparison. | R1A patch is candidate only; planner and real serial equivalence still not validated. |
| Finalized height starts at zero | 5C rerun returns optimistic height for explicit zero and nested zero. | Establish production procedure scheduler's effective finality height at genesis and replay. |
| Conflicting committed clock and local manifest | 5C reproduces local manifest overriding committed clock in fixture. | Verify deployment manifest pinning and independent build/replay at unequal local profiles. |

The recovery-ID experiment is an actual differential observation from two equivalent synthetic record sets with differing insertion order. The other rows identify possible causal chains, not observed node divergence. A false-positive in an isolated guard can be contained by a later fail-closed guard. The full signed transaction path, finality, state persistence and authority cannot be inferred from helper/predicate results alone.

## 6. Phase 5 new checks and historical reruns

| Group | New checks | Passed | Failed |
|---|---:|---:|---:|
| 5A-area (custody/session) | 15 | 12 | 3 |
| 5D-area (recovery/independence) | 37 | 32 | 5 |
| 5E-area (observer/evidence) | 29 | 22 | 7 |
| 5F-area (economics/SYSTEM/sync) | 37 | 34 | 3 |
| **Fresh re-audit** | **118** | **100** | **18** |
| 5B recovered harness rerun | 22 | 14 | 8 |
| 5C recovered harness rerun | 31 | 19 | 12 |
| **Executed in this pass** | **171** | **133** | **38** |

Five separate mathematical model checks passed. Do not add the 171 current checks to the historical 167: 53 are explicit reruns and the 118 fresh checks are new scenarios. Equal or greater quantity than missing historical checks does not imply equivalent scope. Original Phase 5A/D/E/F case identifiers and individual outputs remain unavailable. Their thematic areas are revisited, not every historical assertion. In particular, many frontend, media, governance, real sync installation, baseline readiness, production signature and acceptance concerns are not fully exercised.

The new failures implicate ten numbered topics: TN-025,031,054,055,057,058,062,079,080,081 (not a count of distinct verified exploits). Some rows are direct discrepancies with code; others compare a stronger safety expectation to a synthetic dependency or policy. No new numbered IDs or severity changes are assigned on this basis. The source excerpts, runnable scripts, row-level JSON and text results are included. The recovered 5B/C harnesses remain in `harnesses/` in the parent archive and fresh rerun logs are under `evidence/historical_reruns/`.

## 7. Phase 6 recursion and closure criteria

The cross-domain problem remains inconsistent authority and boundary semantics rather than merely isolated failed predicates. Re-audit of `admit_block_txs` confirms nonce bookkeeping against the initial ledger with a nonce-adjusted admission view; `block_replay` executes sequentially and distinguishes SYSTEM failures from ordinary apply failures. Signed authorization after same-block key revocation must be resolved at the policy-defined effective boundary, not presumed exploitable. Fresh source reads show `effective_poh_tier` gates on status and expiry, while governance's active-membership calculation reads legacy `poh_tier`; production lifecycle/snapshot policy still requires verification. Reviewer responsibility status must be reconciled with sanctions in other role domains. Zero-finality and helper path conflicts remain directly reproduced but not remediated at the audited commit.

The immediate R1A patch remains uncommitted. Before moving to public readiness, prove that the planned R1B planner and helper-merge corrections preserve serial semantics through normal and adversarial execution, then independently test canonical time/finality and signed authority transitions. A finding is closed only after accepted intended policy, negative regressions in a real transaction path, exact-commit CI, and independent-node tests when required. Retain each original finding ID, evidence scope, proposed fix and closure criteria. Additive evidence does not authorize changes to the protocol or constitutional rules.

## 8. Outstanding audit coverage

The historical narrative for some findings remains label-only in the R0 register. The full repository checkout, exhaustive transaction-to-handler mapping, full original scenario IDs, 114 original individual experiment records, 60 exact historic invariant sentences, and independent production-level validation remain unavailable. The newly constructed evidence is useful but not a full equivalent of every lost original report. Complete production validation still requires the checked-out baseline, real dependencies, actual signed envelopes, durable database tests, real IPFS and browser journeys, and independent nodes. No original experimental failures are erased; no PASS result clears a composite release gate. Public participatory testnet: **NO-GO**.


---

## Preserved file: `reaudit/README.md`

# Re-audit supplement — start here

Pinned baseline: `6d3d69234415d294936d99e819367cff589ced3d`. Read `REAUDIT_REPORT.md` first. The parent archive preserves all 41 files from Recovery II. This directory is new evidence, not original historical transcripts.

- `INVARIANTS.tsv`: sixty reconstructed verification targets with separate REINV identifiers, exact or historical source locators, and scoped evidence status.
- `finding_reaudit_crosswalk.tsv`: all 81 existing finding IDs, fresh check mappings and historical reruns; no finding closed.
- `transaction_domain_counts.tsv`: pinned transaction index origin/domain/context counts.
- `source/`: checksum-matched excerpts; none are replacement repository files.
- `run_reaudit.py`, `run_reaudit_batch2.py`: offline diagnostic scripts; Python 3.10+; no external network or package dependencies. Run the first before the second from this directory. Both report all assertions, including failures, and write evidence; zero process exit is not a PASS verdict.
- `evidence/`: original newly generated logs, JSON, TSV, function manifests and the recovered-harness rerun logs. Phase 5B and 5C harnesses are in the parent `harnesses/` directory.

Re-audit counts: 118 fresh checks (100 passed, 18 failed), 53 repeated historical source checks (33 passed, 20 failed), plus five separate model controls. Do not merge these with 167 historic checks. Full production checkout and independent-node integration not available. Some stronger test expectations represent proposed policy and provider trust assumptions. The prior archive preserves the original counts, gaps, and R1A candidate; no repository changes.

The strongest currently verified boundary is isolated source-excerpt behavior, not production exploitation or formal closure.


---

## Preserved registry: `supplement/master_register_reconciled.tsv`

```tsv
finding_id	prior_provisional_severity	recovered_label	proposed_primary_phase	status	evidence_provenance	proposed_acceptance_objective
TN-001	P0	Unsigned seed registry	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject unauthenticated discovery records; verify independent peer discovery.
TN-002	P0	Cloudflare registry verification	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify signatures and chain binding at deployed registry boundary.
TN-003	P0	Observer forwarding boundary	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove observer cannot gain write or consensus authority through forwarding.
TN-004	P0	Controlled-testnet mechanism gates	R7	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify production configuration cannot enable unsafe controlled-testnet paths.
TN-005	P1	Artifact regeneration	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Rebuild committed derivatives from clean checkout and compare digests.
TN-006	P0	Deployment configuration	R7	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject unsafe or conflicting production settings before service starts.
TN-007	P1	Frontend deployment validation	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Validate deployed build and real browser API journey at pinned revision.
TN-008	P1	Independent acceptance evidence	R7	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Repeat fresh-clone acceptance with independent operators and retain logs.
TN-009	P0	Genesis cryptographic authority	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove exact genesis authority, credential binding and expiry on independent nodes.
TN-010	P1	Registration resource protection	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Establish bounded unauthenticated registration and rejection without resource exhaustion.
TN-011	P0	First canonical solo finality	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify initial finality proof and transition to multi-validator epochs.
TN-012	P0	Constitutional clock enforcement	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject off-slot or unauthorized time advances at build and replay boundaries.
TN-013	P0	Role-dependent block replay	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify equal block replay results across node roles.
TN-014	P1	Premature procedural time progression	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify procedures cannot advance on unfinalized height.
TN-015	P0	Session bearer exposure in blockchain history	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Demonstrate public history contains no reusable bearer credentials.
TN-016	P0	Human uniqueness and reviewer selection	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Demonstrate uniqueness constraints and authorized reviewer assignment under adversarial cases.
TN-017	P1	Reputation Matrix authorization discrepancy	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove reputation mutations require canonical provenance and authority.
TN-018	P1	Verification status consistency	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Compare effective PoH, mirrors, eligibility transitions and snapshots across domains.
TN-019	P0	Ballot confidentiality	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify public ledger and API cannot reveal protected voter-choice linkage under specified threat model.
TN-020	P0	Automatic bans circumventing severe-sanction safeguards	R3	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove severe sanctions require applicable panel, appeal and enforcement authority.
TN-021	P0	Public testnet governance configuration	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify enabled testnet governance conforms to authorized configuration.
TN-022	P0	Proposal-defined electoral thresholds	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject thresholds outside authorized constitutional bounds.
TN-023	P1	Inconsistent tally criteria	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify identical outcomes across equivalent tally and resolution paths.
TN-024	P1	Group membership due process	R3	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Ensure membership discipline requires applicable notice, review and authorization.
TN-025	P0	Media integrity and conflicting CID declarations	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject inconsistent commitments; verify returned bytes against expected CID.
TN-026	P1	Media replacement invalidates integrity metadata	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Ensure replacements update or invalidate metadata atomically.
TN-027	P0	Storage capacity accounting bypass	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Enforce quotas across all admitted storage paths.
TN-028	P0	Evidence deletion attestation integrity	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Require verifiable evidence deletion attestation and authorized provenance.
TN-029	P1	Incomplete storage resource isolation	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Demonstrate tenant/resource isolation under contention.
TN-030	P0	Untrusted media MIME types	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Ensure active or unsafe media is rejected or rendered within safe isolation.
TN-031	P0	Economic activation restrictions	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove economic mutations remain disabled until authorized activation conditions hold.
TN-032	P1	Transfer identifier collision	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify domain separation, uniqueness and idempotence of transfer identifiers.
TN-033	P1	Reward distribution conservation	R5	OPEN	E2 reported; retrieved Phase 5B result text: R21,R22	Reject nonconserving distributions; validate scheduler provenance and atomicity.
TN-034	P1	Economic readiness reporting	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject placeholder policies and incomplete activation requirements.
TN-035	P1	Storage compensation settlement	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify compensation only for authorized measured settlement, exactly once.
TN-036	P1	Monetary supply reconciliation	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reconcile issued supply, balances, burns if authorized, and all monetary states.
TN-037	P1	Peer-store saturation	R6	OPEN	E2 reported; retrieved Phase 5C result text: peer store saturation	Verify bounded peer rotation and discovery under saturated hostile fixtures.
TN-038	P1	Multi-hop peer discovery failure	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Demonstrate safe discovery and synchronization beyond bootstrap peers.
TN-039	P1	Peer advertisement temporal validation	R6	OPEN	E2 reported; retrieved Phase 5C result text: zero start/expiry	Validate time bounds and signatures, including missing and zero values.
TN-040	P1	Network-loop resource exhaustion	R6	OPEN — source reconfirmed; production reproduction pending	History summary Phase 1G 2026-11-19 23:16:05 UTC; exact-commit static source recheck net/net_loop.py; supplement/TN-040.md	Bound response size, total deadline and refresh workload; demonstrate unrelated network processing remains responsive under slow/oversized seed responses.
TN-041	P1	Peer persistence failure reporting	R6	OPEN	E2 reported; retrieved Phase 5C result text: persistence failure	Surface write failures without falsely reporting durability.
TN-042	P1	Historical transaction visibility after checkpoint recovery	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify required historical visibility and explicit pruning behavior after recovery.
TN-043	P1	Synchronization verification after durable commitment	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject unauthenticated history before durable commitment or prove safe rollback.
TN-044	P1	Intergenerational historical preservation	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify required archival history survives multi-generation recovery.
TN-045	P1	Incorrect recovery agreement calculation	R6	OPEN	E2 reported in Phase 5A history; original output and harness unavailable	Verify agreement formula and boundary cases against authorized policy.
TN-046	P1	Incomplete historical integrity verification at startup	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject or quarantine corrupted history before serving authoritative state.
TN-047	P1	Helper receipt semantic verification	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject validly signed but semantically invalid helper outputs.
TN-048	P1	Execution manifest authentication	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify authenticated canonical execution manifest and replay binding.
TN-049	P1	Helper certificate recovery	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify restart recovery and receipt/certificate replay safety.
TN-050	P1	Helper timeout enforcement	R1	OPEN	E2 reported; retrieved Phase 5C result text: missing timestamp	Verify missing and boundary timestamps cannot bypass timeout policy.
TN-051	P1	Inconsistent ledger references	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify canonical ledger references across execution, restart and replay.
TN-052	P1	Hierarchical state conflict detection	R1	OPEN	E2 reported; retrieved Phase 5C result text: hierarchical and alias overlaps	Detect normalized-path and ancestor/descendant hazards; prove serial equivalence.
TN-053	P0	Raw session credentials in canonical transactions	R2	OPEN	E2 reported in Phase 5A history; original output and harness unavailable	Reject reusable credentials at canonical transaction and history boundaries.
TN-054	P1	Device revocation leaves sessions active	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove revoked device sessions cannot authenticate after effective revocation.
TN-055	P1	Unbounded session lifetime	R2	OPEN	E2 reported in Phase 5A history; original output and harness unavailable	Enforce bounded expiration against canonical session policy.
TN-056	P1	Recovery-induced account denial of service	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove only legitimate recovery can restrict accounts; demonstrate restoration path.
TN-057	P1	Failed recovery reversal can leave account locked	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify recovery failure is atomic and restoration cannot strand accounts.
TN-058	P1	Encrypted evidence intake validation	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Validate encrypted evidence structure, binding and safe failure paths.
TN-059	P1	Premature PoH submission reconciliation	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Require canonical evidence and submission confirmation before completion.
TN-060	P1	Incorrect reviewer-readiness representation	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Match displayed readiness to effective reviewer entitlement.
TN-061	P1	Inconsistent transaction confirmation requirements	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Require consistent finality confirmation for frontend transaction lifecycles.
TN-062	P1	Observer queue discards unresolved transactions	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Retain unresolved transactions or expose explicit terminal disposition.
TN-063	P1	Upstream transaction rejection not reconciled	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Propagate upstream rejection and reconcile local status.
TN-064	P1	Unsafe automatic retry	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify retry idempotence and ambiguity handling.
TN-065	P1	Inconsistent node identity	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify canonical node identity across API, transport and persistence.
TN-066	P1	Insufficient quorum bounds	R4	OPEN	E2 reported; retrieved Phase 5B result text: R12	Prove authorized minimum quorum at every proposal creation and resolution boundary.
TN-067	P1	Constitutional deliberation can be abbreviated	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Enforce minimum authorized deliberation windows against finalized time.
TN-068	P1	Incomplete historical proposal version commitments	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Bind proposal semantics and decision evidence to immutable historical versions.
TN-069	P1	Incorrect constitutional version ordering	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify canonical amendment ordering, replay and activation.
TN-070	P1	Incorrect ballot-context commitments	R4	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Bind ballot authorization to correct election, scope, version and context.
TN-071	P1	Inconsistent governance approval semantics	R4	OPEN	E2 reported; retrieved Phase 5B result text: R16	Require equivalent early and deadline rules for each authorized proposal type.
TN-072	P1	Multi-option expiration counting	R4	OPEN	E2 reported; retrieved Phase 5B result text: R14	Verify multi-option tally and expiration semantics against authorized rules.
TN-073	P1	Fraudulent storage proof	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject fabricated possession/availability proofs under specified threat model.
TN-074	P1	Receipt validation	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject malformed, misbound and replayed receipts at all applicable boundaries.
TN-075	P1	Reputation reversal	R5	OPEN	E2 reported; retrieved Phase 5B result text: R25,R26	Demonstrate deterministic correction with saturation and intervening events.
TN-076	P1	Predictable dispute panels	R3	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Verify selection resists applicable manipulation and conflict-of-interest threats.
TN-077	P1	Unbounded rejected-certificate accounting	R1	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Bound rejection accounting without compromising safety or diagnostics.
TN-078	P1	Local manifest precedence over canonical clock policy	R1	OPEN	E2 reported; retrieved Phase 5C result text: manifest precedence	Reject conflicting configuration or enforce canonical agreement across nodes.
TN-079	P1	Ambiguous account-recovery identifiers	R2	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Prove identity resolution is unique and unauthorized recovery cannot target aliases.
TN-080	P1	Reversal requests escape expiration	R5	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Enforce authorized reversal deadlines and reject unauthorized late mutation.
TN-081	P1	Malformed upstream confirmation acceptance	R6	OPEN	Prior Phase 6D label only; original narrative and proof pending retrieval	Reject malformed, misbound or unauthenticated confirmations.
```


---

## Preserved registry: `audit/r0/candidate_register.tsv`

```tsv
tracking_id	label	proposed_phase	possible_overlap_not_adjudicated	prior_source_locator_or_result	proposed_acceptance_objective
R0-C01	Effective PoH versus legacy electorate	R2	TN-018; TN-021	runtime/poh/state.py#L200-L279; runtime/apply/governance.py#L647-L735; runtime/apply/groups.py#L1478-L1574	Signed status transitions and snapshot semantics; verify actual voter authorization.
R0-C02	Reviewer sanctions not reflected in lane eligibility	R3	TN-017; TN-020	runtime/reviewer_responsibilities.py#L164-L198; runtime/apply/dispute.py#L3342-L3398; runtime/apply/poh.py#L2220-L2280	Apply legitimate accountability action and verify subsequent assignment and vote authorization.
R0-C03	Dispute quorum contraction	R3	TN-020; TN-076	runtime/apply/dispute.py#L837-L983	Compare v1 and v2 for withdrawal, replacement, incomplete panels, and resolution; no policy activation implied.
R0-C04	Emissary seating eligibility and treasury availability	R4	TN-021; TN-024	runtime/apply/groups.py#L1478-L1574; runtime/apply/groups.py#L1755-L1947	Verify eligible candidates at authorized lifecycle points; verify valid signer threshold after seating.
R0-C05	Account recovery across institutional authority	R2	TN-054; TN-056; TN-057	runtime/apply/identity.py#L1258-L1367	Verify role-specific transitions and quorum availability, not unconditional role revocation.
R0-C06	Stale same-block authority	R1	TN-009; TN-013	runtime/block_admission.py#L323-L477; runtime/block_replay.py#L690-L770; runtime/apply/identity.py#L547-L591	Establish authorized effective boundary and verify signed ordering, leader/follower/helper outcomes.
R0-C07	Explicit zero finality falls back to optimistic height	R1	TN-014; TN-012	runtime/constitutional_clock.py#L172-L191	Verify explicit zero versus absent finality at procedure and production scheduler boundaries.
ADV-006	Placeholder economic policy readiness	R5	TN-031; TN-034	Phase 5B R18	Verify readiness rejects incomplete policies; prove activation path fails closed.
```


---

## Preserved registry: `reaudit/INVARIANTS.tsv`

```tsv
new_id	family	verification_target	source_locator	current_evidence	status
REINV-001	Consensus	Only canonical authorized block transactions may be admitted by the consensus boundary.	runtime/block_admission.py:323-469; generated/tx_index.json	Fresh static read; system binding RA-059–071	OPEN
REINV-002	Consensus	Validator votes and quorum certificates must be bound to the relevant chain, epoch, view and proposal.	Historical TN-009/TN-011; consensus-related transaction catalog	Historical concern only; exact verifier not rerun	OPEN
REINV-003	Consensus	A finalized block and its state root must be invariant across independent validators.	runtime/block_replay.py:690-770; net/state_sync.py:702-788	Fresh static; no multinode execution	OPEN
REINV-004	Consensus	Constitutional procedure height must preserve explicit zero finality rather than use optimistic height.	runtime/constitutional_clock.py:172-190	5C rerun explicit zero and nested zero fail	FAILING_EXCERPT
REINV-005	Consensus	Block clock policy used in build and replay must be derived from the same committed authority.	runtime/block_time_admission.py:72-113	5C rerun TN-078 fails with conflicting manifest	FAILING_EXCERPT
REINV-006	Consensus	A trusted sync anchor cannot be treated as independently verified finality without its required commitments and verification context.	net/state_sync.py:405-438;702-788	RA-072–080 comparator controls; caller completeness not tested	OPEN
REINV-007	Deterministic execution	The same authorized block and parent state must yield the same result for every node role.	runtime/block_admission.py:323-469; runtime/block_replay.py:690-770	Static trace; no full replay	OPEN
REINV-008	Deterministic execution	A transaction ID cannot occur twice in an admitted block.	runtime/block_admission.py:384-400	Fresh static duplicate-ID check; no production test	OPEN
REINV-009	Deterministic execution	Ordinary transactions must follow a contiguous per-signer nonce sequence.	runtime/block_admission.py:426-468	Fresh static check	OPEN
REINV-010	Deterministic execution	A failed SYSTEM operation must not silently commit a partially valid block.	runtime/block_replay.py:701-750	Fresh static read	OPEN
REINV-011	Deterministic execution	State lookup must be independent of map insertion order or reject ambiguous identifiers.	runtime/apply/identity.py:893-914	RA-025–026 fail: duplicate ID selects first account	FAILING_EXCERPT
REINV-012	Deterministic execution	Same-block authorization transitions must have an explicit consistent effective boundary.	runtime/block_admission.py:453-460; runtime/block_replay.py:708-751; historical identity.py:547-591	Fresh static; candidate R0-C06; no signed sequence	OPEN
REINV-013	Authorization	SYSTEM operations must be associated with an existing deterministic queue entry.	runtime/system_tx_engine.py:1072-1127	RA-059–062 pass; dependency doubles	CONTROL_PASS
REINV-014	Authorization	SYSTEM execution height and phase must match the queue and payload.	runtime/system_tx_engine.py:1072-1127	RA-063–065 pass	CONTROL_PASS
REINV-015	Authorization	SYSTEM signer, parent and payload must agree with the scheduled operation.	runtime/system_tx_engine.py:1072-1127	RA-066–068 pass	CONTROL_PASS
REINV-016	Authorization	Revocation must disable the authority at the policy-defined boundary.	runtime/apply/identity.py:659-770; api/security.py:139-181	RA-094 device-linked fixture fails; RA-095 explicit revocation passes	CONDITIONAL_FAIL
REINV-017	Authorization	Observer forwarding must not independently confer validator or ledger authority.	api/routes_public_parts/tx.py:1121-1155;1362-1468	Source parser controls; historical TN-003; full auth path not rerun	OPEN
REINV-018	Identity	An expired or non-active verification status cannot confer active Tier2+ authority.	runtime/poh/state.py:200-220; runtime/apply/governance.py:647-735	Fresh source mismatch with legacy tier; R0-C01 reachability open	OPEN
REINV-019	Identity	An accepted recovery request must resolve exactly one account and record.	runtime/apply/identity.py:893-914	RA-023–026; duplicate lookup failure	FAILING_EXCERPT
REINV-020	Identity	Reviewers must meet eligibility requirements and be independent of the target.	runtime/recovery_review.py:63-109	RA-001–017 pass; PoH/lane fixtures	CONTROL_PASS
REINV-021	Identity	Recovery panel assignment must be deterministic and meet its full requested size.	runtime/recovery_review.py:112-146	RA-018–021 pass; pool fixture	CONTROL_PASS
REINV-022	Identity	Recovery expiry and failed receipt must terminate the request and implement its authorized account-lock policy.	runtime/account_recovery_scheduler.py:51-176; runtime/apply/identity.py:2122-2159	RA-097,105,106 fail in fixture; policy/reachability open	CONDITIONAL_FAIL
REINV-023	Reputation	Score changes must remain within the canonical numeric bounds.	Phase 5B clamp excerpt; runtime reputation implementation per recovered harness	5B R24–26; bounded value observed but exact reversal fails	OPEN
REINV-024	Reputation	Reversal must remove the applied reputation effect without creating a residual penalty or benefit.	Phase 5B clamp/reversal excerpts	5B R25–26 fail near saturation	FAILING_EXCERPT
REINV-025	Reputation	Severe sanctions must follow authorized dispute and appeal procedure rather than an implicit threshold bypass.	Historical TN-020; Phase 6A recovery; runtime/apply/dispute.py:837-983	Prior source trace; not rerun here	OPEN
REINV-026	Reputation	Review accountability sanctions must be reflected in the applicable responsibility lane and role views.	runtime/reviewer_responsibilities.py:164-198; historical dispute.py:3342-3398 and poh.py:2220-2280	Fresh lane predicate read plus historical sanction trace; R0-C02	OPEN
REINV-027	Reputation	Eligibility must be based on the same canonical reputation and effective identity state at all authority boundaries.	runtime/poh/state.py:200-220; runtime/apply/governance.py:647-735; historical TN-017/018	Fresh static identity comparison; reputation matrix not fully rerun	OPEN
REINV-028	Governance	Voter eligibility must follow authorized effective identity and membership semantics.	runtime/apply/governance.py:647-735; runtime/poh/state.py:200-220	Fresh static mismatch; R0-C01	OPEN
REINV-029	Governance	Quorum cannot be weakened below controlling policy by proposal-local settings.	Phase 5B quorum excerpt: runtime/apply/governance.py	R11–12 illustrative floor; controlling bound policy not proven	CONDITIONAL_FAIL
REINV-030	Governance	All valid ballot types must be counted consistently in resolution.	Phase 5B counts excerpt: runtime/gov_engine.py	R13–14 fail for multi-option fixture	FAILING_EXCERPT
REINV-031	Governance	Early and deadline resolution must have compatible approval semantics.	Phase 5B early/deadline excerpts	R15–16 inconsistent paths	FAILING_EXCERPT
REINV-032	Governance	Election results must not seat persons in roles for which they are ineligible.	Historical runtime/apply/groups.py:1478-1574;1755-1947	R0-C04; source previously reported; no rerun here	OPEN
REINV-033	Governance	Protected ballots must satisfy the authorized privacy model and count only entitled humans.	Historical TN-019/021/023; transaction catalog GOV_VOTE_CAST	Prior concern only; exact ballot commitment/privacy path untested	OPEN
REINV-034	Monetary policy	Total supply must never exceed 21,000,000 WCN in the audited cap fixture.	Phase 5B mint excerpt; recovered harness	R27–32 cap controls pass; real issuance untested	CONTROL_PASS
REINV-035	Monetary policy	Economic transfers and activation cannot occur before the canonical unlock time.	runtime/econ_phase.py:65-96;164-196	RA-044–051,54 pass lock cases	CONTROL_PASS
REINV-036	Monetary policy	Economic activation must also satisfy the applicable chain-profile prohibition and typed policy state.	runtime/econ_phase.py:65-96;164-196	RA-052,053,058 fail with synthetic marker/flag; upstream gate unknown	CONDITIONAL_FAIL
REINV-037	Monetary policy	An issuance epoch must not mint twice.	Phase 5B mint excerpt	R28–29 controls pass	CONTROL_PASS
REINV-038	Monetary policy	Distributions must conserve aggregate balances except explicitly authorized supply changes.	Phase 5B distribution excerpt	R19–23; R21–22 fail debit/credit conservation	FAILING_EXCERPT
REINV-039	Monetary policy	Economic readiness must require complete usable policy data rather than placeholders.	Phase 5B readiness excerpt	R17–18 placeholder failure; activation integration untested	FAILING_EXCERPT
REINV-040	Monetary policy	Scheduled issuance and economic accounting must be reproducible and reconcile to policy.	Phase 5B monetary model; runtime/ledger tokenomics sources per earlier report	Five mathematical model checks pass, runtime settlement open	OPEN
REINV-041	Helper execution	Cross-lane writes to ancestor and descendant paths must conflict.	runtime/helper_merge.py:243-277	5C TN-052 fails; R1A candidate separately tested	FAILING_EXCERPT
REINV-042	Helper execution	Cross-lane read/write dependencies include hierarchical overlap.	runtime/helper_merge.py:243-261	5C TN-052 fails	FAILING_EXCERPT
REINV-043	Helper execution	Equivalent slash paths must have equivalent conflict semantics.	runtime/helper_merge.py:243-287	5C TN-052 fails; R1A candidate prepared	FAILING_EXCERPT
REINV-044	Helper execution	Disjoint state paths should not be falsely classified as conflicting solely due to shared string prefix.	runtime/helper_merge.py:243-261	5C disjoint sibling control passes	CONTROL_PASS
REINV-045	Helper execution	Materialized results must be bound to coordinator-local plans and accepted certificates.	Historical runtime/helper_merge.py: verification path; TN-047/048	R1A source review; no new integrated verification	OPEN
REINV-046	Helper execution	Missing timing evidence cannot open an overdue helper execution window.	Phase 5C runtime/helper_dispatch.py:298-322	5C TN-050 fails on absent timestamp	FAILING_EXCERPT
REINV-047	Helper execution	A conflicting, missing or rejected helper result must fall back to canonical serial execution.	Historical runtime/helper_merge.py merge_materialized_lane_results; helper_apply.py	R1A scoped candidate; end-to-end fallback not rerun	OPEN
REINV-048	Helper execution	Independent nodes must agree on roots, receipts and outcome under helper/serial execution and recovery.	Historical TN-049/051/052; helper safety reference	No independent multinode test	OPEN
REINV-049	Cryptography and privacy	New account session records store a domain-separated hash rather than a raw bearer.	runtime/session_keys.py:13-66	RA-081–082 pass; raw transaction history exposure still open	CONTROL_PASS
REINV-050	Cryptography and privacy	Reusable credentials must not persist in public canonical transaction history.	runtime/apply/identity.py:687-745; runtime/session_keys.py:13-66; TN-015/053	Raw payload consumed by issuance; actual persisted block redaction not tested	OPEN
REINV-051	Cryptography and privacy	Evidence intake must bind exact object bytes and enforce declared privacy requirements.	api/routes_public_parts/poh.py:154-252	RA-107–118; hash/MIME controls pass; encryption/provider trust probes fail	CONDITIONAL_FAIL
REINV-052	Persistence	Reported persistence failures cannot be treated as successful durable writes.	Phase 5C net/peer_list_store.py:1-141	5C TN-041 fails	FAILING_EXCERPT
REINV-053	Persistence	Trusted checkpoint commitments must be verified before irreversible incompatible state installation.	net/state_sync.py:702-788; historical TN-043	Fresh verify_response source check; terminal apply ordering not rerun	OPEN
REINV-054	Persistence	Restored historical state must retain and independently verify commitments required for replay and queries.	Historical TN-042/044/045/046; net/state_sync.py:702-788	No crash/restart or database validation in this turn	OPEN
REINV-055	Networking	Peer storage bounds must not permanently prevent discovery of independent authorized peers.	Phase 5C net/peer_list_store.py:1-141	5C TN-037 saturated store fails	FAILING_EXCERPT
REINV-056	Networking	Peer advertisements must be authentic, chain-bound and temporally valid.	Phase 5C net/gossip.py:274-331	5C TN-039 zero fields fail; signature fixture only	FAILING_EXCERPT
REINV-057	Networking	Discovery and relay work must not block the consensus network loop or allocate unbounded response data.	Historical TN-040; net/net_loop.py:256-277;711-764;903-925	Prior exact source read; no live resource test	OPEN
REINV-058	Frontend and API	Private API session access must reject wrong accounts, revoked keys and expired sessions under a finite policy.	api/security.py:139-181; runtime/apply/identity.py:687-745	RA-083–095; zero/missing TTL fails fixture	CONDITIONAL_FAIL
REINV-059	Frontend and API	Observer queue bounds must not silently destroy unresolved transaction tracking; failures must be surfaced.	api/routes_public_parts/tx.py:503-578	RA-034,036 fail; bounded fixture	FAILING_EXCERPT
REINV-060	Frontend and API	An upstream confirmation must be typed, bound to the requested transaction and validated against committed state before being presented as final.	api/routes_public_parts/tx.py:1121-1155;1362-1468	RA-041–043 parser fails stronger expectation; later commitment verifier has independent checks	CONDITIONAL_FAIL
```


---

## Preserved registry: `reaudit/finding_reaudit_crosswalk.tsv`

```tsv
finding_id	prior_label	fresh_check_ids	fresh_pass	fresh_fail	historical_harness_rerun	scope_note
TN-001	Unsigned seed registry		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-002	Cloudflare registry verification		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-003	Observer forwarding boundary		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-004	Controlled-testnet mechanism gates		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-005	Artifact regeneration		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-006	Deployment configuration		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-007	Frontend deployment validation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-008	Independent acceptance evidence		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-009	Genesis cryptographic authority		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-010	Registration resource protection		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-011	First canonical solo finality		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-012	Constitutional clock enforcement		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-013	Role-dependent block replay		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-014	Premature procedural time progression		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-015	Session bearer exposure in blockchain history		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-016	Human uniqueness and reviewer selection		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-017	Reputation Matrix authorization discrepancy		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-018	Verification status consistency		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-019	Ballot confidentiality		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-020	Automatic bans circumventing severe-sanction safeguards		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-021	Public testnet governance configuration		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-022	Proposal-defined electoral thresholds		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-023	Inconsistent tally criteria		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-024	Group membership due process		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-025	Media integrity and conflicting CID declarations	RA-118	0	1		New scoped source-excerpt checks; read scope and report before classification
TN-026	Media replacement invalidates integrity metadata		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-027	Storage capacity accounting bypass		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-028	Evidence deletion attestation integrity		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-029	Incomplete storage resource isolation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-030	Untrusted media MIME types		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-031	Economic activation restrictions	RA-044,RA-045,RA-046,RA-047,RA-048,RA-049,RA-050,RA-051,RA-052,RA-053,RA-054,RA-055,RA-056,RA-057,RA-058	12	3		New scoped source-excerpt checks; read scope and report before classification
TN-032	Transfer identifier collision		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-033	Reward distribution conservation		0	0	5B	Recovered isolated harness rerun only
TN-034	Economic readiness reporting		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-035	Storage compensation settlement		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-036	Monetary supply reconciliation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-037	Peer-store saturation		0	0	5C	Recovered isolated harness rerun only
TN-038	Multi-hop peer discovery failure		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-039	Peer advertisement temporal validation		0	0	5C	Recovered isolated harness rerun only
TN-040	Network-loop resource exhaustion		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-041	Peer persistence failure reporting		0	0	5C	Recovered isolated harness rerun only
TN-042	Historical transaction visibility after checkpoint recovery		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-043	Synchronization verification after durable commitment		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-044	Intergenerational historical preservation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-045	Incorrect recovery agreement calculation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-046	Incomplete historical integrity verification at startup		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-047	Helper receipt semantic verification		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-048	Execution manifest authentication		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-049	Helper certificate recovery		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-050	Helper timeout enforcement		0	0	5C	Recovered isolated harness rerun only
TN-051	Inconsistent ledger references		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-052	Hierarchical state conflict detection		0	0	5C	Recovered isolated harness rerun only
TN-053	Raw session credentials in canonical transactions	RA-081	1	0		New scoped source-excerpt checks; read scope and report before classification
TN-054	Device revocation leaves sessions active	RA-094	0	1		New scoped source-excerpt checks; read scope and report before classification
TN-055	Unbounded session lifetime	RA-090,RA-093	0	2		New scoped source-excerpt checks; read scope and report before classification
TN-056	Recovery-induced account denial of service		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-057	Failed recovery reversal can leave account locked	RA-105,RA-106	0	2		New scoped source-excerpt checks; read scope and report before classification
TN-058	Encrypted evidence intake validation	RA-117	0	1		New scoped source-excerpt checks; read scope and report before classification
TN-059	Premature PoH submission reconciliation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-060	Incorrect reviewer-readiness representation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-061	Inconsistent transaction confirmation requirements		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-062	Observer queue discards unresolved transactions	RA-027,RA-028,RA-029,RA-030,RA-031,RA-032,RA-033,RA-034,RA-035,RA-036	8	2		New scoped source-excerpt checks; read scope and report before classification
TN-063	Upstream transaction rejection not reconciled		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-064	Unsafe automatic retry		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-065	Inconsistent node identity		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-066	Insufficient quorum bounds		0	0	5B	Recovered isolated harness rerun only
TN-067	Constitutional deliberation can be abbreviated		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-068	Incomplete historical proposal version commitments		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-069	Incorrect constitutional version ordering		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-070	Incorrect ballot-context commitments		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-071	Inconsistent governance approval semantics		0	0	5B	Recovered isolated harness rerun only
TN-072	Multi-option expiration counting		0	0	5B	Recovered isolated harness rerun only
TN-073	Fraudulent storage proof		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-074	Receipt validation		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-075	Reputation reversal		0	0	5B	Recovered isolated harness rerun only
TN-076	Predictable dispute panels		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-077	Unbounded rejected-certificate accounting		0	0		No new individual executable check in this pass; original register retained; static review may exist
TN-078	Local manifest precedence over canonical clock policy		0	0	5C	Recovered isolated harness rerun only
TN-079	Ambiguous account-recovery identifiers	RA-023,RA-024,RA-025,RA-026	2	2		New scoped source-excerpt checks; read scope and report before classification
TN-080	Reversal requests escape expiration	RA-097	0	1		New scoped source-excerpt checks; read scope and report before classification
TN-081	Malformed upstream confirmation acceptance	RA-037,RA-038,RA-039,RA-040,RA-041,RA-042,RA-043	4	3		New scoped source-excerpt checks; read scope and report before classification
```


---

## Preserved registry: `reaudit/evidence/ALL_FRESH_CHECKS.tsv`

```tsv
id	group	finding	label	expected	actual	status	scope
RA-001	5D-area	RECOVERY-CONTROL	independent reviewer	null	null	PASS	isolated source excerpt
RA-002	5D-area	RECOVERY-CONTROL	missing reviewer	"""missing_identity"""	"""missing_identity"""	PASS	isolated source excerpt
RA-003	5D-area	RECOVERY-CONTROL	self review	"""self_review"""	"""self_review"""	PASS	isolated source excerpt
RA-004	5D-area	RECOVERY-CONTROL	prior reviewer	"""prior_case_reviewer"""	"""prior_case_reviewer"""	PASS	isolated source excerpt
RA-005	5D-area	RECOVERY-CONTROL	unknown account	"""unknown_account"""	"""unknown_account"""	PASS	isolated source excerpt
RA-006	5D-area	RECOVERY-CONTROL	institutional reviewer	"""institutional_account"""	"""institutional_account"""	PASS	isolated source excerpt
RA-007	5D-area	RECOVERY-CONTROL	institutional target	"""institutional_account"""	"""institutional_account"""	PASS	isolated source excerpt
RA-008	5D-area	RECOVERY-CONTROL	banned reviewer	"""reviewer_unavailable"""	"""reviewer_unavailable"""	PASS	isolated source excerpt
RA-009	5D-area	RECOVERY-CONTROL	locked reviewer	"""reviewer_unavailable"""	"""reviewer_unavailable"""	PASS	isolated source excerpt
RA-010	5D-area	RECOVERY-CONTROL	low tier	"""reviewer_tier2_required"""	"""reviewer_tier2_required"""	PASS	isolated source excerpt
RA-011	5D-area	RECOVERY-CONTROL	inactive lane	"""reviewer_lane_required"""	"""reviewer_lane_required"""	PASS	isolated source excerpt
RA-012	5D-area	RECOVERY-CONTROL	shared household	"""shared_household"""	"""shared_household"""	PASS	isolated source excerpt
RA-013	5D-area	RECOVERY-CONTROL	reviewer financial dependency	"""financial_dependency"""	"""financial_dependency"""	PASS	isolated source excerpt
RA-014	5D-area	RECOVERY-CONTROL	target financial dependency	"""financial_dependency"""	"""financial_dependency"""	PASS	isolated source excerpt
RA-015	5D-area	RECOVERY-CONTROL	reviewer conflict	"""declared_conflict"""	"""declared_conflict"""	PASS	isolated source excerpt
RA-016	5D-area	RECOVERY-CONTROL	target conflict	"""declared_conflict"""	"""declared_conflict"""	PASS	isolated source excerpt
RA-017	5D-area	RECOVERY-CONTROL	institution overlap	"""shared_institution"""	"""shared_institution"""	PASS	isolated source excerpt
RA-018	5D-area	RECOVERY-CONTROL	full independent panel	"[""@r"", ""@s""]"	"[""@r"", ""@s""]"	PASS	isolated source excerpt
RA-019	5D-area	RECOVERY-CONTROL	order-independent scoring	"[""@r"", ""@s""]"	"[""@r"", ""@s""]"	PASS	isolated source excerpt
RA-020	5D-area	RECOVERY-CONTROL	insufficient pool fail closed	[]	[]	PASS	isolated source excerpt
RA-021	5D-area	RECOVERY-CONTROL	excluded prior reviewer cannot fill panel	[]	[]	PASS	isolated source excerpt
RA-022	5D-area	RECOVERY-CONTROL	only recognized review decisions count	[1, 1, 2]	[1, 1, 2]	PASS	isolated source excerpt
RA-023	5D-area	TN-079	single request resolves	"""@a"""	"""@a"""	PASS	isolated source excerpt
RA-024	5D-area	TN-079	unknown request rejects	"""rejected"""	"""rejected"""	PASS	isolated source excerpt
RA-025	5D-area	TN-079	duplicate request id fails closed	"""rejected"""	"""@a"""	FAIL	isolated source excerpt
RA-026	5D-area	TN-079	same records in reverse insertion order resolve identically	"""@a"""	"""@b"""	FAIL	isolated source excerpt
RA-027	5E-area	TN-062	invalid/non-id rows dropped	"[""a""]"	"[""a""]"	PASS	isolated source excerpt
RA-028	5E-area	TN-062	expired pending dropped	[]	[]	PASS	isolated source excerpt
RA-029	5E-area	TN-062	stale confirmed dropped	[]	[]	PASS	isolated source excerpt
RA-030	5E-area	TN-062	old pending TTL applied	[]	[]	PASS	isolated source excerpt
RA-031	5E-area	TN-062	old accepted survives TTL	"[""a""]"	"[""a""]"	PASS	isolated source excerpt
RA-032	5E-area	TN-062	recent confirmed kept	"[""a""]"	"[""a""]"	PASS	isolated source excerpt
RA-033	5E-area	TN-062	record cap bounds count	"[""b"", ""c""]"	"[""b"", ""c""]"	PASS	isolated source excerpt
RA-034	5E-area	TN-062	record cap preserves unresolved accepted over newer confirmed	"[""a"", ""c""]"	"[""b"", ""c""]"	FAIL	isolated source excerpt
RA-035	5E-area	TN-062	byte budget prefers removing confirmed	"[""a""]"	"[""a""]"	PASS	isolated source excerpt
RA-036	5E-area	TN-062	byte budget does not silently drop unresolved accepted	"[""a"", ""b""]"	"[""b""]"	FAIL	isolated source excerpt
RA-037	5E-area	TN-081	matching valid response	true	true	PASS	HTTP parser only; downstream verification not exercised
RA-038	5E-area	TN-081	wrong ID	false	false	PASS	HTTP parser only; downstream verification not exercised
RA-039	5E-area	TN-081	list shape	false	false	PASS	HTTP parser only; downstream verification not exercised
RA-040	5E-area	TN-081	negative upstream status	false	false	PASS	HTTP parser only; downstream verification not exercised
RA-041	5E-area	TN-081	confirmed success without ID	false	true	FAIL	HTTP parser only; downstream verification not exercised
RA-042	5E-area	TN-081	string false rejected	false	true	FAIL	HTTP parser only; downstream verification not exercised
RA-043	5E-area	TN-081	confirmed success without height or receipt	false	true	FAIL	HTTP parser only; downstream verification not exercised
RA-044	5F-area	TN-031	pre-unlock disabled	false	false	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-045	5F-area	TN-031	pre-unlock enabled	false	false	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-046	5F-area	TN-031	at unlock disabled	false	false	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-047	5F-area	TN-031	at unlock enabled	true	true	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-048	5F-area	TN-031	post unlock enabled	true	true	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-049	5F-area	TN-031	missing time	false	false	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-050	5F-area	TN-031	missing genesis and unlock	false	false	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-051	5F-area	TN-031	malformed time	false	false	PASS	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-052	5F-area	TN-031	public-testnet mode after unlock should remain locked	false	true	FAIL	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-053	5F-area	TN-031	malformed truthy string false should deny	false	true	FAIL	primitive only; profile field is synthetic, upstream types and launch gates not exercised
RA-054	5F-area	TN-031	activation before lock ends	"""denied"""	"""denied"""	PASS	primitive only; production launch matrix not exercised
RA-055	5F-area	TN-031	activation at unlock	"""allowed"""	"""allowed"""	PASS	primitive only; production launch matrix not exercised
RA-056	5F-area	TN-031	transfer without activation	"""denied"""	"""denied"""	PASS	primitive only; production launch matrix not exercised
RA-057	5F-area	TN-031	transfer enabled	"""allowed"""	"""allowed"""	PASS	primitive only; production launch matrix not exercised
RA-058	5F-area	TN-031	public testnet transfer post unlock	"""denied"""	"""allowed"""	FAIL	primitive only; production launch matrix not exercised
RA-059	5F-area	SYSTEM-CONTROL	valid	"[true, """"]"	"[true, """"]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-060	5F-area	SYSTEM-CONTROL	missing queue ID	"[false, ""missing_system_queue_id""]"	"[false, ""missing_system_queue_id""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-061	5F-area	SYSTEM-CONTROL	unknown queue ID	"[false, ""unknown_system_queue_id""]"	"[false, ""unknown_system_queue_id""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-062	5F-area	SYSTEM-CONTROL	wrong type	"[false, ""system_queue_tx_type_mismatch""]"	"[false, ""system_queue_tx_type_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-063	5F-area	SYSTEM-CONTROL	wrong due height	"[false, ""system_queue_due_height_mismatch""]"	"[false, ""system_queue_due_height_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-064	5F-area	SYSTEM-CONTROL	wrong payload due height	"[false, ""system_payload_due_height_mismatch""]"	"[false, ""system_payload_due_height_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-065	5F-area	SYSTEM-CONTROL	wrong phase	"[false, ""system_queue_phase_mismatch""]"	"[false, ""system_queue_phase_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-066	5F-area	SYSTEM-CONTROL	wrong signer	"[false, ""system_queue_signer_mismatch""]"	"[false, ""system_queue_signer_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-067	5F-area	SYSTEM-CONTROL	wrong parent	"[false, ""system_queue_parent_mismatch""]"	"[false, ""system_queue_parent_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-068	5F-area	SYSTEM-CONTROL	wrong payload hash	"[false, ""system_queue_payload_mismatch""]"	"[false, ""system_queue_payload_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-069	5F-area	SYSTEM-CONTROL	wrong emitted height	"[false, ""system_queue_emitted_height_mismatch""]"	"[false, ""system_queue_emitted_height_mismatch""]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-070	5F-area	SYSTEM-CONTROL	same emitted height	"[true, """"]"	"[true, """"]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-071	5F-area	SYSTEM-CONTROL	zero emitted height	"[true, """"]"	"[true, """"]"	PASS	binding function; queue validation and lineage dependencies stubbed
RA-072	5F-area	SYNC-CONTROL	all six fields match	true	true	PASS	isolated source excerpt
RA-073	5F-area	SYNC-CONTROL	mismatched height	false	false	PASS	isolated source excerpt
RA-074	5F-area	SYNC-CONTROL	mismatched tip_hash	false	false	PASS	isolated source excerpt
RA-075	5F-area	SYNC-CONTROL	mismatched state_root	false	false	PASS	isolated source excerpt
RA-076	5F-area	SYNC-CONTROL	mismatched finalized_height	false	false	PASS	isolated source excerpt
RA-077	5F-area	SYNC-CONTROL	mismatched finalized_block_id	false	false	PASS	isolated source excerpt
RA-078	5F-area	SYNC-CONTROL	mismatched snapshot_hash	false	false	PASS	isolated source excerpt
RA-079	5F-area	SYNC-SCOPE	partial pin compares only provided field	true	true	PASS	isolated source excerpt
RA-080	5F-area	SYNC-SCOPE	empty pin compares no fields; caller must enforce completeness	true	true	PASS	isolated source excerpt
RA-081	5A-area	TN-053	new session state stores hash, not raw bearer	false	false	PASS	isolated source excerpt
RA-082	5A-area	SESSION-CONTROL	valid bearer resolves hashed record	"""@a"""	"""@a"""	PASS	isolated source excerpt
RA-083	5A-area	SESSION-CONTROL	wrong bearer denied	"""session_invalid"""	"""session_invalid"""	PASS	isolated source excerpt
RA-084	5A-area	SESSION-CONTROL	missing bearer denied	"""session_missing"""	"""session_missing"""	PASS	isolated source excerpt
RA-085	5A-area	SESSION-CONTROL	wrong account denied	"""session_invalid"""	"""session_invalid"""	PASS	isolated source excerpt
RA-086	5A-area	SESSION-CONTROL	revoked bearer denied	"""session_revoked"""	"""session_revoked"""	PASS	isolated source excerpt
RA-087	5A-area	SESSION-CONTROL	before expiration accepted	"""@a"""	"""@a"""	PASS	isolated source excerpt
RA-088	5A-area	SESSION-CONTROL	after expiration denied	"""session_expired"""	"""session_expired"""	PASS	isolated source excerpt
RA-089	5A-area	SESSION-CONTROL	missing chain time rejects positive TTL	"""session_expired"""	"""session_expired"""	PASS	isolated source excerpt
RA-090	5A-area	TN-055	zero TTL cannot remain usable indefinitely	"""session_expired"""	"""@a"""	FAIL	isolated source excerpt
RA-091	5A-area	SESSION-CONTROL	policy caps requested TTL	60	60	PASS	isolated source excerpt
RA-092	5A-area	SESSION-CONTROL	policy sets omitted TTL	60	60	PASS	isolated source excerpt
RA-093	5A-area	TN-055	omitted TTL with no policy should acquire finite lifetime	true	false	FAIL	isolated source excerpt
RA-094	5A-area	TN-054	device revocation invalidates its synthetic associated bearer	"""session_revoked"""	"""@a"""	FAIL	synthetic linked session; production association policy not established
RA-095	5A-area	SESSION-CONTROL	explicit session revocation denies API request	"""session_revoked"""	"""session_revoked"""	PASS	isolated source excerpt
RA-096	5D-area	RECOVERY-CONTROL	continuity social attestations expire	"""expired"""	"""expired"""	PASS	isolated source excerpt
RA-097	5D-area	TN-080	reversal awaiting social attestations expires	"""expired"""	"""awaiting_social_attestations"""	FAIL	isolated source excerpt
RA-098	5D-area	RECOVERY-CONTROL	under-review reversal expires	"""expired"""	"""expired"""	PASS	isolated source excerpt
RA-099	5D-area	RECOVERY-CONTROL	deadline height remains reviewable	"""under_review"""	"""under_review"""	PASS	isolated source excerpt
RA-100	5D-area	RECOVERY-CONTROL	insufficient panel fails assignment	"""assignment_unavailable"""	"""assignment_unavailable"""	PASS	isolated source excerpt
RA-101	5D-area	RECOVERY-CONTROL	complete panel assigned	"""under_review"""	"""under_review"""	PASS	isolated source excerpt
RA-102	5D-area	RECOVERY-CONTROL	threshold approval schedules finalization	"""approved"""	"""approved"""	PASS	isolated source excerpt
RA-103	5D-area	RECOVERY-CONTROL	mathematically impossible approval rejects	"""rejected"""	"""rejected"""	PASS	isolated source excerpt
RA-104	5D-area	RECOVERY-CONTROL	failed continuity receipt unlocks account and records receipt	"[false, null, ""receipt_recorded""]"	"[false, null, ""receipt_recorded""]"	PASS	isolated source excerpt
RA-105	5D-area	TN-057	failed reversal receipt should release lock and active request	"[false, null, ""receipt_recorded""]"	"[true, null, ""receipt_recorded""]"	FAIL	synthetic initially locked reversal; alternative unlock policy/path unresolved
RA-106	5D-area	TN-057	expired reversal receipt should release lock	"[false, null, ""receipt_recorded""]"	"[true, null, ""receipt_recorded""]"	FAIL	synthetic initially locked reversal; alternative unlock policy/path unresolved
RA-107	5E-area	UPLOAD-CONTROL	valid commitment and permitted MIME	"""ok"""	"""ok"""	PASS	route function; provider and session dependencies stubbed
RA-108	5E-area	UPLOAD-CONTROL	disabled endpoint	"""endpoint_disabled"""	"""endpoint_disabled"""	PASS	route function; provider and session dependencies stubbed
RA-109	5E-area	UPLOAD-CONTROL	missing session principal (stubbed)	"""denied"""	"""denied"""	PASS	route function; provider and session dependencies stubbed
RA-110	5E-area	UPLOAD-CONTROL	wrong algorithm	"""client_side_aes_256_gcm_required"""	"""client_side_aes_256_gcm_required"""	PASS	route function; provider and session dependencies stubbed
RA-111	5E-area	UPLOAD-CONTROL	malformed context hash	"""invalid_encryption_context_commitment"""	"""invalid_encryption_context_commitment"""	PASS	route function; provider and session dependencies stubbed
RA-112	5E-area	UPLOAD-CONTROL	wrong MIME	"""encrypted_ciphertext_file_required"""	"""encrypted_ciphertext_file_required"""	PASS	route function; provider and session dependencies stubbed
RA-113	5E-area	UPLOAD-CONTROL	empty object	"""empty_file"""	"""empty_file"""	PASS	route function; provider and session dependencies stubbed
RA-114	5E-area	UPLOAD-CONTROL	oversize object	"""file_too_large (max 8 bytes)"""	"""file_too_large (max 8 bytes)"""	PASS	route function; provider and session dependencies stubbed
RA-115	5E-area	UPLOAD-CONTROL	mismatched commitment	"""ciphertext_commitment_mismatch"""	"""ciphertext_commitment_mismatch"""	PASS	route function; provider and session dependencies stubbed
RA-116	5E-area	UPLOAD-CONTROL	invalid reported CID	"""invalid_cid_from_ipfs:fixture"""	"""invalid_cid_from_ipfs:fixture"""	PASS	route function; provider and session dependencies stubbed
RA-117	5E-area	TN-058	arbitrary plaintext labeled as AES ciphertext is rejected	"""rejected"""	"""ok"""	FAIL	trust-boundary probe; absence of a server proof of encryption is not necessarily a route bug
RA-118	5E-area	TN-025	provider-reported size discrepancy rejected instead of accepted	"""rejected"""	"""ok"""	FAIL	synthetic provider discrepancy; actual IPFS behavior and CID validation not tested
```
