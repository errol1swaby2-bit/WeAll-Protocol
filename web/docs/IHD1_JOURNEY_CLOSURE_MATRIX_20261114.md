# IHD-1 journey implementation matrix — provisional source triage (2026-11-14)

**Base:** draft PR #88 head `eaa34f4d9d4ffca885bd2076defe2b57aa157abd`; `web/docs/FRONTEND_V16_PRODUCT_SPEC.md` §6; `FRONTEND_V16_IMPLEMENTATION_STATUS.md`; frontend source and named tests; backend README and group-election safety evidence. This stacked branch implements a bounded J20 increment.

**Evidence status:** This matrix is **not** a completed repository-wide audit or evidence of integration. The inventory lists candidate contracts only where the source reviewed supports them. Every row remains open until the actual backend handler/registry mapping, exact-head CI, and end-to-end behavior have been examined. A test *file's presence* is not a passing result. No COMPLETE — VERIFIED assertions. The five canonical status labels are used below; no new authority is inferred.

## J01 — First-time account setup · PARTIAL

- **1. Required user-facing functionality:** First-time account setup
- **2. Existing frontend routes/components:** LoginPage, AccountVerificationPage
- **3. Existing backend APIs (candidate; validate):** /v1/session/login; /v1/accounts; /v1/tx/status
- **4. Canonical transaction type(s):** ACCOUNT_REGISTER
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** account_custody_registration_restore.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Fresh user signed inclusion, backup, restart and independent inspection not verified
- **11. Constitutional/cryptographic blockers:** None for Tier 0; enforce account scarcity
- **12. Dependencies:** node -> key -> admission -> receipt
- **13. Estimated implementation complexity:** L (estimate; unverified)
- **14. Recommended implementation order:** 1

## J02 — Restore to a new device · IMPLEMENTED — NOT INTEGRATED

- **1. Required user-facing functionality:** Restore to a new device
- **2. Existing frontend routes/components:** LoginPage; auth/session.ts; auth/recoveryFile.ts
- **3. Existing backend APIs (candidate; validate):** /v1/session/login; account state
- **4. Canonical transaction type(s):** No new registration; session login
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** account_custody_registration_restore.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Two actual devices, no duplicate registration, fresh bearer and signing need proof
- **11. Constitutional/cryptographic blockers:** External HTTPS node and independent browser access
- **12. Dependencies:** J01 -> HTTPS -> restored signer
- **13. Estimated implementation complexity:** L (estimate; unverified)
- **14. Recommended implementation order:** 3

## J03 — Verified Person async · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Verified Person async
- **2. Existing frontend routes/components:** AccountVerificationPage
- **3. Existing backend APIs (candidate; validate):** /v1/poh/async/*
- **4. Canonical transaction type(s):** POH_ASYNC_REQUEST_OPEN; EVIDENCE_DECLARE; EVIDENCE_BIND
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** poh_async_independent_browsers.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Real capture, private upload, assigned review and canonical finality
- **11. Constitutional/cryptographic blockers:** Production positive humanity/uniqueness authority closed
- **12. Dependencies:** J01 -> encrypted storage -> J05
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 12

## J04 — Trusted Verified Person live · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Trusted Verified Person live
- **2. Existing frontend routes/components:** LiveVerificationRoom; AccountVerificationPage
- **3. Existing backend APIs (candidate; validate):** /v1/poh/live/*
- **4. Canonical transaction type(s):** Live request/vote types: review registry
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** poh_live_independent_browsers.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Cross-device live streams, signed review, terminal case
- **11. Constitutional/cryptographic blockers:** Production positive humanity/uniqueness authority closed
- **12. Dependencies:** J03 -> room -> J06
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 13

## J05 — Async evidence reviewer · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Async evidence reviewer
- **2. Existing frontend routes/components:** JurorDashboard; EncryptedEvidenceViewer
- **3. Existing backend APIs (candidate; validate):** /v1/poh/async/juror-cases
- **4. Canonical transaction type(s):** Reviewer verdict contract to inspect
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_reviewer_critical_flows_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Real assignee authorization, conflict-safe decrypt and signed receipt
- **11. Constitutional/cryptographic blockers:** Positive PoH production review authority
- **12. Dependencies:** J03 -> assignment -> evidence -> verdict
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 14

## J06 — Live reviewer · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Live reviewer
- **2. Existing frontend routes/components:** JurorDashboard; LiveVerificationRoom
- **3. Existing backend APIs (candidate; validate):** /v1/poh/live/assigned
- **4. Canonical transaction type(s):** Assigned reviewer verdict contract to inspect
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_live_room_join_truth.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Actual remote attendance, no post-terminal join and committed review
- **11. Constitutional/cryptographic blockers:** Production reviewer/PoH gates
- **12. Dependencies:** J04 -> assignment -> room -> verdict
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 15

## J07 — Publish and discuss · PARTIAL

- **1. Required user-facing functionality:** Publish and discuss
- **2. Existing frontend routes/components:** Feed; CreatePostPage; Post; Thread
- **3. Existing backend APIs (candidate; validate):** /v1/feed; /v1/thread/:id
- **4. Canonical transaction type(s):** Social post/comment types: inspect registry
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** social_core_human_first.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Signed post, inclusion, second-account read and restart
- **11. Constitutional/cryptographic blockers:** Eligible account PoH/reputation may be unavailable in production
- **12. Dependencies:** J01 -> J18 -> eligible author
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 5

## J08 — Report a post · PARTIAL

- **1. Required user-facing functionality:** Report a post
- **2. Existing frontend routes/components:** Post; Disputes; My Reports
- **3. Existing backend APIs (candidate; validate):** /v1/disputes
- **4. Canonical transaction type(s):** CONTENT_FLAG
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_content_flag_report_truth.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Reporter follows case independently of assigned juror
- **11. Constitutional/cryptographic blockers:** Conflicts/recusal and dispute rules
- **12. Dependencies:** J07 -> J12
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 8

## J09 — Discover join participate · PARTIAL

- **1. Required user-facing functionality:** Discover join participate
- **2. Existing frontend routes/components:** Groups; Group
- **3. Existing backend APIs (candidate; validate):** /v1/groups/:id
- **4. Canonical transaction type(s):** GROUP_MEMBERSHIP_REQUEST
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_group_flow_readiness_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Real membership lifecycle across distinct users/receipts
- **11. Constitutional/cryptographic blockers:** Permission/standing remain backend gates
- **12. Dependencies:** J01 -> J18 -> group
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 6

## J10 — Create and administer group · PARTIAL

- **1. Required user-facing functionality:** Create and administer group
- **2. Existing frontend routes/components:** GroupCreate; Group responsibilities
- **3. Existing backend APIs (candidate; validate):** /v1/groups/*
- **4. Canonical transaction type(s):** Group-create type; GROUP_MEMBERSHIP_DECIDE
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_group_governance_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Founder/moderator authority with restart and unauthorized denial
- **11. Constitutional/cryptographic blockers:** No browser-derived group authority
- **12. Dependencies:** J09 -> signed lifecycle
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 7

## J10a — Group-scoped governance · PARTIAL

- **1. Required user-facing functionality:** Group-scoped governance
- **2. Existing frontend routes/components:** Group Decisions; ProposalCreate
- **3. Existing backend APIs (candidate; validate):** /v1/groups/:id/governance-contract; /v1/gov/proposals
- **4. Canonical transaction type(s):** GOV_PROPOSAL_CREATE
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_v16_navigation_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Committed exact group scope and public/global cross-read
- **11. Constitutional/cryptographic blockers:** Eligible group electorate required
- **12. Dependencies:** J10 -> J11 -> J18
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 9

## J10b — Group treasury oversight · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Group treasury oversight
- **2. Existing frontend routes/components:** Group Treasury
- **3. Existing backend APIs (candidate; validate):** /v1/treasury/status; scoped API to verify
- **4. Canonical transaction type(s):** Governance proposals only; no direct spend
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_group_governance_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Canonical scoped balance/mandate/payment receipt absent
- **11. Constitutional/cryptographic blockers:** Economics locked; mandate execution unauthorized
- **12. Dependencies:** J10a -> treasury read contract
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 20

## J10c — Emissary elections/mandates · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Emissary elections/mandates
- **2. Existing frontend routes/components:** Group Elections; GroupBallotPlanner
- **3. Existing backend APIs (candidate; validate):** /v1/groups/:id/elections; /elections/:id
- **4. Canonical transaction type(s):** GROUP_EMISSARY_BALLOT_CAST; ELECTION_FINALIZE
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_group_emissary_ballot_transport_boundary.py
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Live eligibility, ballot secrecy, authorized activation and finality
- **11. Constitutional/cryptographic blockers:** Signed envelope exposes signer/ranking; quorum activation unset
- **12. Dependencies:** J10 -> crypto review -> quorum -> finality
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 22

## J10d — Membership approval/scoped moderation · PARTIAL

- **1. Required user-facing functionality:** Membership approval/scoped moderation
- **2. Existing frontend routes/components:** Group responsibilities/member desk
- **3. Existing backend APIs (candidate; validate):** /v1/groups/:id; group reports
- **4. Canonical transaction type(s):** GROUP_MEMBERSHIP_DECIDE
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_v16_navigation_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Pending list privacy; role changes; signed decision/restart
- **11. Constitutional/cryptographic blockers:** No reporter/juror authority conflation
- **12. Dependencies:** J09 -> J10 -> J18
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 10

## J10e — Treasury mandate transparency · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Treasury mandate transparency
- **2. Existing frontend routes/components:** Group Treasury; records
- **3. Existing backend APIs (candidate; validate):** Mandate/execution projection not confirmed
- **4. Canonical transaction type(s):** No authorized live spend
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_group_governance_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Approved mandate and execution record chain missing
- **11. Constitutional/cryptographic blockers:** Locked economics and mandate approval semantics
- **12. Dependencies:** J10b -> J11
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 21

## J11 — Deliberate and vote · PARTIAL

- **1. Required user-facing functionality:** Deliberate and vote
- **2. Existing frontend routes/components:** Proposals; Proposal
- **3. Existing backend APIs (candidate; validate):** /v1/gov/proposals
- **4. Canonical transaction type(s):** Governance ballot type: inspect registry
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** m3_civic_governance_real_stack.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Eligible distinct voters, canonical outcome and restart
- **11. Constitutional/cryptographic blockers:** PoH/electorate and phase gates
- **12. Dependencies:** J01 -> J18 -> J10a
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 11

## J12 — Dispute and appeal · PARTIAL

- **1. Required user-facing functionality:** Dispute and appeal
- **2. Existing frontend routes/components:** Disputes; DisputeDetail; DisputeReview
- **3. Existing backend APIs (candidate; validate):** /v1/disputes; /v1/disputes/:id
- **4. Canonical transaction type(s):** DISPUTE_OPEN; review/appeal types to inspect
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_dispute_review_rendered_journey_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Full signed review, receipt, conflicts, recusal and replay
- **11. Constitutional/cryptographic blockers:** Fail-closed panel quorum; dormant v2 semantics
- **12. Dependencies:** J08 -> assigned panel -> J18
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 16

## J13 — Inspect reputation and eligibility · PARTIAL

- **1. Required user-facing functionality:** Inspect reputation and eligibility
- **2. Existing frontend routes/components:** Account profile tabs
- **3. Existing backend APIs (candidate; validate):** /v1/reputation/me; /v1/accounts/:account
- **4. Canonical transaction type(s):** Read-only
- **5. Signing/session requirements:** No signer; local settings or public read only.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Local browser preferences or authoritative public read, as appropriate; check device boundary.
- **8. Existing automated tests:** test_account_profile_readiness_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Backend capability parity and role refresh under changes
- **11. Constitutional/cryptographic blockers:** No frontend-computed authority
- **12. Dependencies:** J01 -> account projections
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 17

## J14 — Node operator enrollment · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Node operator enrollment
- **2. Existing frontend routes/components:** NodeDashboard; OperatorCommandWizard
- **3. Existing backend APIs (candidate; validate):** /v1/status/operator; /v1/nodes/validators
- **4. Canonical transaction type(s):** Operator enrollment type: inspect registry
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_node_operator_journey_incident_response_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Distinct node key, enrollment vs activation, restart
- **11. Constitutional/cryptographic blockers:** Public validator/operator activation not approved
- **12. Dependencies:** J01 -> node custody -> J18
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 23

## J15 — Observer synchronization · PARTIAL

- **1. Required user-facing functionality:** Observer synchronization
- **2. Existing frontend routes/components:** NodeDashboard; NodeConnectionPanel
- **3. Existing backend APIs (candidate; validate):** /v1/chain/identity; /v1/observer/edge/status
- **4. Canonical transaction type(s):** Read-only
- **5. Signing/session requirements:** No signer; local settings or public read only.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Local browser preferences or authoritative public read, as appropriate; check device boundary.
- **8. Existing automated tests:** test_node_dashboard_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Restart/catch-up with matched root and independently observed receipts
- **11. Constitutional/cryptographic blockers:** Single host cannot prove decentralized validators
- **12. Dependencies:** node -> connection -> J18
- **13. Estimated implementation complexity:** L (estimate; unverified)
- **14. Recommended implementation order:** 4

## J16 — Storage service opt-in · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Storage service opt-in
- **2. Existing frontend routes/components:** NodeDashboard storage
- **3. Existing backend APIs (candidate; validate):** /v1/storage/ipfs/ops
- **4. Canonical transaction type(s):** Storage enrollment type: inspect registry
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** Backend storage/IPFS tests
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Advertised capacity vs verified/challenged service lifecycle
- **11. Constitutional/cryptographic blockers:** Public provider market not approved
- **12. Dependencies:** J14 -> IPFS -> proof
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 24

## J17 — Understand locked economics · PARTIAL

- **1. Required user-facing functionality:** Understand locked economics
- **2. Existing frontend routes/components:** Economics page
- **3. Existing backend APIs (candidate; validate):** /v1/economics/status; /v1/treasury/status
- **4. Canonical transaction type(s):** None (economic transfer locked)
- **5. Signing/session requirements:** No signer; local settings or public read only.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Local browser preferences or authoritative public read, as appropriate; check device boundary.
- **8. Existing automated tests:** test_economics_block_public_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Public UI and backend consistently reject live transfer
- **11. Constitutional/cryptographic blockers:** Economic lock intentional
- **12. Dependencies:** canonical node status -> public read
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 18

## J18 — Verify signed action/result · PARTIAL

- **1. Required user-facing functionality:** Verify signed action/result
- **2. Existing frontend routes/components:** TransactionsPage; TxStatusToast; ActionLifecycleCard
- **3. Existing backend APIs (candidate; validate):** /v1/tx/status/:id; /v1/chain/identity
- **4. Canonical transaction type(s):** All supported signed state changes
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** tx_submission_clarity.spec.ts
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Signed/queued/included/applied/rejected + restart/second user
- **11. Constitutional/cryptographic blockers:** HTTP accepted is not finality; observer status must converge
- **12. Dependencies:** J01 -> authoritative tx receipts
- **13. Estimated implementation complexity:** L (estimate; unverified)
- **14. Recommended implementation order:** 2

## J19 — Personal application theme · PARTIAL

- **1. Required user-facing functionality:** Personal application theme
- **2. Existing frontend routes/components:** Settings; themePresets; lib/settings.ts
- **3. Existing backend APIs (candidate; validate):** None (browser only)
- **4. Canonical transaction type(s):** None
- **5. Signing/session requirements:** No signer; local settings or public read only.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Local browser preferences or authoritative public read, as appropriate; check device boundary.
- **8. Existing automated tests:** test_v16_navigation_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Contrast, custom tokens, high contrast and real visual testing
- **11. Constitutional/cryptographic blockers:** Themes cannot alter roles, sessions, public profile
- **12. Dependencies:** local settings -> accessibility
- **13. Estimated implementation complexity:** M–L (estimate; unverified)
- **14. Recommended implementation order:** 19

## J20 — Import/preview/restore theme · PARTIAL

- **1. Required user-facing functionality:** Import/preview/restore theme
- **2. Existing frontend routes/components:** Settings; lib/themeTransfer.ts (PR #89)
- **3. Existing backend APIs (candidate; validate):** None (browser only)
- **4. Canonical transaction type(s):** None
- **5. Signing/session requirements:** No signer; local settings or public read only.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Local browser preferences or authoritative public read, as appropriate; check device boundary.
- **8. Existing automated tests:** test_theme_transfer.mjs (new, CI pending)
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Second browser transfer; full safe custom-token editor not delivered
- **11. Constitutional/cryptographic blockers:** No code/CSS/media/network URLs; no automatic sync
- **12. Dependencies:** J19 -> portable safe JSON -> browser
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 25

## J21 — Group appearance · BLOCKED — PROTOCOL

- **1. Required user-facing functionality:** Group appearance
- **2. Existing frontend routes/components:** Group; responsibility desk
- **3. Existing backend APIs (candidate; validate):** Canonical public group style update to verify
- **4. Canonical transaction type(s):** No approved new transaction
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Existing production-profile gate remains effective; do not seed privileged actors outside explicitly labeled fixtures.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** Group/appearance source tests incomplete
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Authorized group update and second-user override lacking
- **11. Constitutional/cryptographic blockers:** Group authority, media/publication contract unresolved
- **12. Dependencies:** J10 -> proposal/mandate -> verified asset
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 26

## J22 — Public personal profile background · PARTIAL

- **1. Required user-facing functionality:** Public personal profile background
- **2. Existing frontend routes/components:** Account profile appearance editor
- **3. Existing backend APIs (candidate; validate):** /v1/accounts/tx/profile-update; /v1/accounts/:account
- **4. Canonical transaction type(s):** PROFILE_UPDATE banner_cid
- **5. Signing/session requirements:** For state-changing journeys, confirm ML-DSA signing, local key custody, nonce, and node-bound session; read-only/local UI has no signature.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Canonical state/receipt must be read after submission, survive restart, and agree with independent observer; browser-only appearance persists locally.
- **8. Existing automated tests:** test_public_profile_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Image upload/crop, inclusion, second account view/restart
- **11. Constitutional/cryptographic blockers:** Existing banner removal unsupported; public media controls
- **12. Dependencies:** J01 -> media CID -> J18
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 27

## J23 — Public-profile viewer readability · PARTIAL

- **1. Required user-facing functionality:** Public-profile viewer readability
- **2. Existing frontend routes/components:** Public Account profile; hide background toggle
- **3. Existing backend APIs (candidate; validate):** /v1/accounts/:account
- **4. Canonical transaction type(s):** Read-only
- **5. Signing/session requirements:** No signer; local settings or public read only.
- **6. Authorization/PoH eligibility:** Check live backend standing, PoH tier, assignment and group scope where applicable; UI may only preflight.
- **7. Persistent state and read models:** Local browser preferences or authoritative public read, as appropriate; check device boundary.
- **8. Existing automated tests:** test_public_profile_source.mjs
- **9. Actual integration evidence:** None newly demonstrated on this exact worktree; test names identify proposed evidence surfaces, not proven passes.
- **10. Missing functionality:** Rendered keyboard/mobile and second-account media fallback
- **11. Constitutional/cryptographic blockers:** Owner appearance never overrides visitor preference
- **12. Dependencies:** J22 -> public read -> viewer toggle
- **13. Estimated implementation complexity:** XL (estimate; unverified)
- **14. Recommended implementation order:** 28

## Dependency-ordered closure and critical path

```text
0. Pin exact source + clean clone -> node ready + HTTPS/CORS/Cloudflare binding
1. J01 signer + Tier-0 account + recoverable backup
2. J18 canonical tx admission/receipt/result/restart + rejection proof
3. J02 independent-device restore + new session, not duplicate registration
4. J15 observer height/tip/state-root/reconciliation truth
5. J07 public post -> J09 group participation -> J10/J10a scopes -> J11 vote
6. J08 report -> J12 assigned review, conflict/recusal, appeal and finality
7. J13 canonical trust/read projections + J17 locked-economics read
8. J19/J20 local visual choices and manual safe portability (non-consensus)
9. J22/J23 public banner canonical publication/readability and media durability
10. J03–J06 production PoH, J10c confidential emissary election, J14/J16 operator/storage,
    J10b/J10e economic execution, J21 group appearance: engineering prep only
    until their distinct constitutional/cryptographic gates are approved.
```

**First acceptance target:** a real Tier-0 account can create/restore signer identity, submit a legitimately allowed signed action, see the canonical receipt and persistent read in a second browser after node restart. This does **not** prove positive human uniqueness or multi-validator finality. If all writes require a closed PoH gate, demonstrate the exact deny path and continue separate non-consensus work rather than fabricating Tier-2 users.

**Explicit limits:** Current Cloudflare DNS/deployment state, credentials, actual physical-device PoH, automatic cross-device appearance sync, independent validation and current 20 unapproved V2 semantics are not established by this document. Existing draft PRs #81/#82/#88 remain NO-GO; this branch is stacked, not a release gate override.

**Refresh rule:** For every row, record exact source refs, reproducible test command, observed tx ID and receipt (redacted), expected and actual state before/after restart, independent-account observation, CI run/commit and unresolved authority question before updating to COMPLETE — VERIFIED.
