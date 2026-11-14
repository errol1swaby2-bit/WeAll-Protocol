# WeAll unified baseline — PR #93 merge and release-readiness docket

**Date:** 2026-11-14. **Target:** `main` via the single **draft** PR #93. **Status:** staged integration, **NO-GO for merge or public release** until required evidence is green. Never treat branch ancestry as proof that every conflicting functional change survived.

## Complete initial open-PR inventory (22)

| Scope | PR heads present in unified merge ancestry | Integration choice |
| --- | --- | --- |
| Core P1, account/session, cases, evidence and versioned semantics | #59, #60, #61, #62, #64, #70, #73, #74, #75, #76, #77, #80, #81 | All ancestors of #92 prior to baseline staging; contemporary #92 behavior retained. |
| Issue68 devnet writable/deletion boundaries | #69 | Second-parent merge of #69; retain later safety implementation from #70/#81. Do **not** add old branch-scoped automatic V2 regeneration/push workflow. |
| Public Cloudflare testnet deployment preparation | #78 | Second-parent merge; import four previously absent deploy docs/config/tests; newer #81/#88 connection, CSP, manifests and generated values take precedence in overlapping files. No deployment authorized. |
| F1/F1b guided onboarding, PoH interruption safety, Genesis witnesses | #82, #86 | Second-parent merge of #82, which already contains #86; import 32 new paths plus 50 non-overlapping updated paths. Resolve overlapping frontend/source paths deliberately. Source lineage alone is not semantic acceptance. |
| Frontend v1.6 and transactional UX | #88, #90, #91, #92 | Ancestors of staging baseline; retain signed Tier-0 browser registration, canonical receipt truth, independent-browser observation, two independent SQLite backend processes and actual restart/replay evidence. |
| Local-only visual theme portability | #89 | Second-parent merge, merge theme export/import controls and focused test stages alongside existing frontend CI and current settings. |

**Exact commit and merge proofs** should be checked against PR #93's Git history and review diff, not inferred from this table alone. Two temporary integration PRs (#94 and #95) were auto-closed after their heads were incorporated; they do not target `main`.

## Specific conflict-resolution decisions

- **CRITICAL — PR #82 vs PR #88/#92 PoH page:** both modified `web/src/pages/AccountVerificationPage.tsx` substantively. Current integration promotes PR #82's fail-closed guided async/live PoH controller into the active page, with URL stage checks and interrupted-submission journals, while retaining the later PR #88 v1.6 screen as `AccountVerificationPageV16Preserved.tsx` for explicit design-parity review. Preserving the old source is **not** evidence that its full UI remains exposed. The public baseline must be reviewed for navigation/UX parity and for any double-submission paths before acceptance.
- PR #82 guided `/onboarding/register` now has explicit `App.tsx`/router wiring. The signer accepts an awaited `onBeforeSubmit` callback to durably record the exact signed registration tx ID before the request is dispatched.
- Session issuance and revocation use canonical successful receipts with explicit `apply_ok=true`, explicit `local_state_synced=true`, and direct `/v1/session/me` bearer authorization checks, instead of accepting a submission acknowledgment or nonce alone.
- PR #82 PoH source security contracts were added to Web CI: safe journal persistence, case history vs unknown distinctions, guarded URL stages and canonical registration identity. The exact HEAD must pass **all** these gates; compiler success alone cannot close a flow.
- PR #78 Cloudflare config/docs remain documentation and nonproduction testnet preparation. It has no right to override current signed seed registry, TLS/CSP, authority or constitutional readiness gates.
- PR #69 obsolete write-capable workflow remains excluded. Generated V2 source/artifact disagreements were **not** auto-regenerated into approvals; all semantic-review digests remain governed by actual reviewer process.
- No protected `main` branch, canonical Genesis signing key, locked-economics parameter, real-world reviewer independence assessment or production block-finalize authorization has been modified or approved by consolidation.

## Merge/NO-GO checklist

A **merge-ready baseline** requires, at minimum:

1. The exact PR #93 head must pass **Web CI** (typecheck, source guards, build, compiled browser), **Backend CI** (Ruff, strict generated artifacts, full backend), **A01–A20 P1**, **Reviewer Readiness**, **Secrets Guard**, and focused F1b/F2 and account custody integrations required by their changes. No skipped optional workflows may be presented as affirmative evidence.
2. Source-level review of all conflicting PR #82/#88/#92 paths must establish the intended runtime behavior; the PR #82 guided PoH page must not silently drop later controls, and the preserved v1.6 page must not be mistaken for an active route.
3. V2 semantic-review digest drift is an **actual review/approval blocker**. Do not regenerate a hash or alter a source map to pass a gate without completing the corresponding substantive source-level adjudication and required signatures/acceptance.
4. Re-run the bounded controlled-devnet rehearsal from an exact fresh clone. Distinct SQLite processes with operator-mediated HTTP delta sync are **not** independent physical devices, authenticated P2P mesh, production quorum certificates or production human-uniqueness authority.
5. Explicit reviewer decision and branch-protection requirements must be satisfied before changing PR #93 from **draft** or merging into `main`. Canonical first `BLOCK_FINALIZE`, public network activation, PoH production advancement and new-economy claims require their separate evidence/constitutional gates.

**Disposition of 22 original PRs:** keep open until the full unified head has acceptable evidence and the scope of omitted/overlapping changes is reviewed. Then mark each as superseded by #93 (or close with documented deferral) to leave a single main-targeting review path. Ancestry consolidation alone must not silence unresolved engineering findings.
