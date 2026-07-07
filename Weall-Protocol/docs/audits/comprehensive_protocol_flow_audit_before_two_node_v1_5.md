# Comprehensive protocol flow audit before two-node rehearsal v1.5

Pass: 29
Purpose: practical pre-rehearsal audit of reviewer-facing truth, first-run user/operator experience, and major protocol-flow UX before the next two-node/public-observer rehearsal.

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.**

This audit does not claim public beta readiness, public mainnet readiness, public multi-validator BFT readiness, live economics readiness, production helper execution readiness, automatic upgrade readiness, legal/compliance approval, or public storage-market readiness.

Boundary reminder: frontend state is not protocol authority, and local scripts are evidence-capture helpers only unless protocol state and external evidence prove the higher claim.

## Inputs inspected

- Root and backend README/release docs: `README.md`, `Weall-Protocol/README.md`, `RELEASE_CHECKLIST.md`.
- Reviewer and go-gate docs: `docs/reviewer/CURRENT_READINESS_STATEMENT.md`, `docs/reviewer/EVIDENCE_INDEX.md`, `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md`, `docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md`.
- First-run/testnet docs: `docs/testnet/FIRST_15_MINUTES.md`, `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md`, `docs/testnet/TESTNET_LAUNCH_CHECKLIST.md`, external transcript runbooks, storage/legal/validator/helper/upgrade plans.
- Generated artifacts: `generated/public_beta_blocker_report_v1_5.json`, `generated/release_evidence_manifest_v1_5.json`, `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`.
- Frontend routes/pages/components: router, Home, Account/Profile, public social, groups, governance, dispute/review, transaction lifecycle, node/operator dashboard, connection manager, Tools/advanced diagnostics.
- Backend/API route surfaces: status, tx, accounts, content/social, groups, governance, disputes, nodes, public protocol policy, tx admission, domain dispatch, testnet capability surface.

## Artifact truth checkpoint

| Check | Current result |
| --- | --- |
| `public_beta_ready` | `false` |
| Blocker catalog entries | `14` |
| Closed in repository | `7` |
| Still open | `7` |
| Remaining external/mainnet-hardening gates | observer transcript, replay transcript, storage/IPFS transcript, independent validator/operator transcript, legal/compliance attestation, executable upgrade hardening, production helper topology hardening |
| Final go-gate scope | controlled internal/public-observer rehearsal candidate only |

## Flow classification table

| # | Flow | Current status | Issue found | Patch action | Remaining evidence/test need |
| ---: | --- | --- | --- | --- | --- |
| 1 | First-run tester onboarding | Frontend readable but needs rendered/runtime test | `FIRST_15_MINUTES.md` had duplicated/out-of-order late sections and clean-clone install skipped `requirements.lock`. | Rewrote the guide into one ordered path and added dependency install before editable install. | Run external/open-download transcript and capture Home/Personal Node/Transactions screenshots. |
| 2 | Public observer boot | Docs complete; external evidence required | Quickstart is clear, but local boot remains preparation evidence only. | No code change; audit report preserves external transcript boundary. | `AUD-628-P1-001` external clean-clone/open-download/state-sync/frontend rendered journey transcript. |
| 3 | Node connection and switching | Frontend readable and source-tested | Connection manager blocks incompatible nodes; no obvious authority overclaim found. | No code change. | Rendered two-node run should prove tester sees chain mismatch/stale-node warnings. |
| 4 | Chain identity/status display | Complete and tested at source level | Status cards expose chain id, height, finalized height, and authority level. | No code change. | Two-node transcript should capture `/v1/status`, `/v1/chain/identity`, and frontend status cards. |
| 5 | Account creation/login/recovery | Frontend readable but needs rendered/runtime test | Flow is visible; account/session recovery must still be tested with a real browser. | No code change. | Capture clean browser session create/restore path and rejection states. |
| 6 | Public account/profile display | Frontend readable and source-tested | No immediate route break found in Account/Profile surface. | No code change. | Render profile empty state and profile update tx lifecycle in controlled rehearsal. |
| 7 | PoH / verification entry and status | Frontend readable; external identity boundaries remain | Verification UI separates eligibility from real-world identity certainty. | No code change. | Capture verification locked/unlocked states; keep counsel/privacy review open. |
| 8 | Public posting/feed | Frontend readable and source-tested | Feed/create surfaces appear public-only and non-finality aware. | No code change. | Submit one low-risk post in rehearsal and track status through Transactions. |
| 9 | Comments/replies/reactions | Backend implemented but UX needs rendered proof | Public replies/reactions appear in feed/detail surfaces, but full rendered tester path still needs real browser evidence. | No code change. | Capture reply/reaction empty, pending, rejected, and reconciled states. |
| 10 | Public content/detail/thread pages | Frontend readable and source-tested | Public detail/thread routes exist; no stale private visibility claim found. | No code change. | Capture direct-link route load and unknown/missing content state. |
| 11 | Public activity trail | Frontend readable but needs rendered/runtime test | Activity is present in nav; needs user-facing no-activity proof. | No code change. | Capture no-activity and populated activity states during rehearsal. |
| 12 | Groups list/detail/create | Frontend readable and source-tested | Public group read visibility and member-gated participation appear consistent. | No code change. | Capture group empty/list/detail/create flow in two-node run. |
| 13 | Group membership and participation permissions | Backend implemented but UX incomplete evidence | Permission boundaries are surfaced, but runtime role transitions need rendered proof. | No code change. | Capture locked action copy, join/leave request, and tx status. |
| 14 | Group governance | Frontend readable and source-tested | Group governance appears route-consistent; group authority remains governance-scoped, not admin-only. | No code change. | Capture one group decision/election surface if data exists. |
| 15 | Emissary election display | Frontend readable but needs rendered/runtime test | Display/election windows exist in source/tests; normal tester data path still needs screenshot evidence. | No code change. | Seed or create election data and capture multi-candidate display. |
| 16 | Governance proposal list/detail/create | Frontend readable and source-tested | Major route labels use Decisions; no legacy `/proposals` alias claim found. | No code change. | Capture list/detail/create with submit outcome and tx lifecycle. |
| 17 | Multi-option voting | Complete in backend tests; UX needs rendered proof | Canonical option IDs are expected, but normal user vote flow needs live verification. | No code change. | Run multi-option proposal and verify status/revocation display. |
| 18 | Governance stage timeline/block-height deadlines | Complete in backend tests; frontend readable | Block-height boundary and wall-clock estimate warning appear present. | No code change. | Capture an active staged proposal and deadline wording. |
| 19 | Protocol/constitution upgrade record-only surfaces | Docs/source complete; execution external hardening open | Record-only boundary is clear; automatic/executable upgrade remains forbidden. | No code change. | `AUD-618-P0-003` future executable upgrade staging/rollback proof. |
| 20 | Dispute list/detail/create | Frontend readable but needs rendered/runtime test | Reports routes are public-readable; create path evidence depends on available content/account state. | No code change. | Capture report creation or honest locked state. |
| 21 | Juror dashboard | Frontend readable and source-tested | Review Center separates lanes; query-route behavior is supported. | No code change. | Capture assigned/empty lane states with account eligibility. |
| 22 | Dispute review/vote flow | Frontend readable and source-tested | Review actions appear signed and non-final; needs end-to-end two-node evidence. | No code change. | Capture accept/decline/vote pending and reconciled states. |
| 23 | Dispute timeout/withdrawal/appeal/finalization display | Backend implemented but UX incomplete evidence | Lifecycle wording exists; full timeout/appeal/finalization path is not practical in first 15 minutes. | No code change. | Add focused rendered/replay evidence after two-node baseline. |
| 24 | Transaction lifecycle status | Frontend readable and source-tested | Lifecycle distinguishes submitted, locally accepted, pending, included, finalized/confirmed, rejected, removed, unknown. | No code change. | Rehearsal should capture at least one pending/rejected or confirmed example. |
| 25 | Transaction queue/toast/timeline | Frontend readable and source-tested | Toast copy preserves non-finality boundary. | No code change. | Render after real mutation during two-node test. |
| 26 | Node/operator dashboard | Frontend readable and source-tested | Operator dashboard carries status/authority warnings. | No code change. | Capture node dashboard during seed/observer sync and any failure recovery. |
| 27 | Operator command wizard | Frontend readable and source-tested | Commands are labeled diagnostic/local/observer/protocol-state-bound. | No code change. | Tester should copy no command that grants authority without protocol state. |
| 28 | Operator incident timeline | Frontend readable and source-tested | Incident guidance exists and points to read-only diagnostics. | No code change. | Run incident packet capture if two-node boot fails or stalls. |
| 29 | Public observer open-download transcript docs | Docs complete; external evidence required | Template/runbook is present, but not completed. | No code change. | Completed `AUD-628-P1-001` external transcript package. |
| 30 | External replay transcript docs | Docs complete; external evidence required | Template/runbook is present, but not completed. | No code change. | Completed two external/physical machine replay transcript for `AUD-618-P1-003`. |
| 31 | Storage/IPFS operator transcript docs | Docs complete; external evidence required | Template/runbook is present, but no public storage-market claim is allowed. | No code change. | Real storage/IPFS daemon/operator transcript for `AUD-618-P1-004`. |
| 32 | Independent validator/operator transcript docs | Docs complete; external evidence required | Template/runbook is present, but validator/public BFT claim remains blocked. | No code change. | Independent validator/operator transcript for `AUD-618-P0-001`. |
| 33 | Legal/compliance evidence pack | Docs incomplete for approval; external evidence required | Legal pack is non-lawyer preparation only. | No code change. | Counsel or controlled external attestation for `AUD-618-P0-002`. |
| 34 | Upgrade execution hardening plan | Future mainnet-hardening gate | Record-only surfaces are present; executable upgrade/migration/rollback remains disabled. | No code change. | Implement and prove staged upgrade execution in a separate hardening pass. |
| 35 | Production helper topology hardening plan | Future mainnet-hardening gate | Helper topology remains a future proof; production helper execution stays disabled. | No code change. | Serial equivalence, Byzantine rejection, deterministic merge, crash/restart, and multi-node helper evidence. |
| 36 | Final go-gate package | Complete for bounded rehearsal; public beta blocked | Generated go-gate allows only controlled internal/public-observer rehearsal candidate wording. | No code change. | Keep blocker report fresh and attach external transcripts before claim escalation. |

## Closed in this pass

* flow/issue: Advanced Tools page stale route targets for session recovery and create-post shortcuts.
* evidence: `web/src/pages/Tools.tsx` previously navigated to `/session-devices` and `/post`, neither of which is a valid normal route.
* tests: `web/scripts/test_step9_p2_ux_source.mjs` now asserts the fixed `/session` and `/create` routes and rejects the stale targets.

* flow/issue: First-run runbook was confusing because late sections repeated numbered headings after the allowed readiness statement.
* evidence: `docs/testnet/FIRST_15_MINUTES.md` had duplicate out-of-order sections after the main journey.
* tests: `web/scripts/test_first_run_tester_journey_source.mjs` and `tests/test_release_docs_truth_sync.py` now check the ordered guide, dependency install, and pre-rehearsal audit coverage.

## Reduced in this pass

* flow/issue: Clean-clone first-run instructions skipped `pip install -r requirements.lock`.
* what improved: `FIRST_15_MINUTES.md` now mirrors the public observer quickstart dependency install before editable install.
* what remains: a real external tester still needs to run the command and capture dependency output.

* flow/issue: Reviewer evidence map did not point at this comprehensive flow audit.
* what improved: `docs/reviewer/EVIDENCE_INDEX.md` now links this pass-29 audit as pre-rehearsal flow classification evidence.
* what remains: This audit is local repository evidence only; it does not close external blockers.

## Still open

* flow/issue: Public observer launch evidence.
* why: local scripts and founder-run checks cannot prove external open-download success.
* exact evidence or patch needed: completed `docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md` package for `AUD-628-P1-001`.

* flow/issue: Cross-machine replay evidence.
* why: repo-local checks cannot prove external replay consistency across independent machines.
* exact evidence or patch needed: aggregate external cross-machine replay transcript for `AUD-618-P1-003`.

* flow/issue: Storage/IPFS operator evidence.
* why: local browser media or simulated storage is not public storage-market proof.
* exact evidence or patch needed: real daemon/operator transcript for `AUD-618-P1-004`.

* flow/issue: Public validator/operator safety and public multi-validator BFT.
* why: controlled local readiness is not independent validator evidence.
* exact evidence or patch needed: independent controlled validator/operator transcript for `AUD-618-P0-001`.

* flow/issue: Legal/compliance approval.
* why: checked-in legal docs are preparation drafts, not counsel approval.
* exact evidence or patch needed: counsel or controlled external attestation for `AUD-618-P0-002`.

* flow/issue: Automatic/executable protocol upgrades.
* why: current surfaces are record-only and must remain non-executing.
* exact evidence or patch needed: separate upgrade hardening pass with staged activation, migration, rollback, and replay proof for `AUD-618-P0-003`.

* flow/issue: Production helper topology.
* why: helper readiness remains diagnostic/future hardening and production execution is disabled.
* exact evidence or patch needed: helper topology proof package for `AUD-618-P1-005`.

## Safe next action for the maintainer

1. Run source/docs checks for this patch.
2. Commit only after generated artifacts remain fresh and release hygiene passes with `--allow-dirty` during patch review.
3. Run the next two-node/public-observer rehearsal and capture the first external-style transcript artifacts.
4. Do not close any of the seven remaining external/mainnet-hardening blockers without the exact evidence listed above.
