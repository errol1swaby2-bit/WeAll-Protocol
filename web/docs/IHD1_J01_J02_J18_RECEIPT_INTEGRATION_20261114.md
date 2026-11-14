# IHD-1 account and transaction closure — receipt-first integration candidate

**Date:** 2026-11-14. **Stack:** draft PR #91 → #90 → #88 → #81. This is an unmerged source and CI candidate, not a launch authorization or complete IHD-1 proof.

## Exact source paths and observed safety gaps

1. `Weall-Protocol/src/weall/api/routes_public_parts/tx.py::tx_status` returns `confirmed` with `apply_ok=true` for a canonical successful indexed receipt; `rejected` with `apply_ok=false` for deterministic failed apply; an included-block header fallback may report `apply_ok=null` when a successful apply receipt is not proven.
2. `web/src/lib/status.ts::normalizeTxStatus` (PR #90) requires explicit `apply_ok===true` and no false local-state sync before representing final success; it exposes failed receipts as failed.
3. `web/src/components/TxQueueProvider.tsx::monitorFinality` previously had an alternate path: a `reconcile()` callback could return `phase=confirmed` solely because a related domain object was visible. That was promoted to a successful toast and `confirmed` mutation despite missing canonical receipt, bypassing the improved normalizer. Conversely, a canonical `rejected`/failed-apply status did not have an explicit terminal-failure branch, and a submission without a transaction ID could be promoted to success.
4. `web/src/pages/AccountVerificationPage.tsx::reconcileRegisteredState`, `reconcileSessionKeyVisible`, `reconcileVerificationLevel`, `reconcileAsyncCompatibilityCase` are examples of **read-model visibility** checks. Their `phase=confirmed` is useful reconciliation evidence but must not certify the specific submitted transaction.

## Bounded changes

- `web/src/lib/txReconciliation.ts` is a pure classifier: every read-model observation is **nonterminal**. An apparently confirmed object remains “checking successful canonical apply receipt”; domain-reported failure is not automatically treated as transaction rejection. A different reported tx ID cannot replace the original signed action.
- `TxQueueProvider` only calls `markSuccess` after `normalizeTxStatus` returns confirmed from `weall.txStatus(originalTxId)`. Its explicit failed branch now renders deterministic failed receipts and mutation failures instead of waiting and degrading them to pending. After a late domain observation it **rechecks the original canonical status**, never a second domain read as a substitute.
- Missing tx IDs stay recorded/unverified, not successful. Nonce reservation and signed envelopes are untouched.
- `web/scripts/test_tx_reconciliation_truth.mjs` dynamically executes the real pure reconciliation classifier and checks the provider's callback/unknown-ID and canonical-status guards.
- `web/tests/e2e/account_custody_registration_restore.spec.ts` now requires explicit `confirmed`, `apply_ok=true`, a committed block identifier, positive height, and no false local sync. It adds an independent browser profile with no local signer/session to check the **same** public receipt and updated public profile after the restored browser signs a profile change. This test closes/reopens the *browser context*, not the node.
- A separate `ihd1-account-custody-real-stack.yml` CI job runs this existing real-browser scenario against a freshly generated **controlled-devnet-only** local Genesis/block-producer API, with real ML-DSA browser custody, a signed Tier-0 registration and profile update. It uses pinned backend and frontend dependencies and forbids demo secret routes, direct session mutation and production credentials.

## Proof boundaries / remaining gaps

- The CI result must be checked at the **exact head SHA**; a workflow existing in source is not a passing run.
- The controlled local producer is **one host and fixture-seeded Genesis authority**. The separate observer browser uses the same node API. It does not establish independent validators, PoH uniqueness, remote media, node restart or consensus QCs.
- The test's protected action is a signed profile update, not an end-to-end PoH advancement. Tier-1/2 positive production authority is deliberately closed pending uniqueness and constitutional review.
- The CI runs with `WEALL_REQUIRE_REAL_ACCOUNT_CUSTODY_E2E=1`: backend absence fails rather than skipping. Any resulting boot or data mismatch must be diagnosed, not waived or downgraded to a synthetic success.
- An additional scoped CI step now **actually stops and restarts the same controlled-devnet backend without resetting its database or operator keyfile**, then calls `scripts/verify_ihd1_receipts_after_restart.py` against a public-only witness from the browser. It must recover both original successful receipts at the identical heights/block IDs, the same canonical ML-DSA authority digest, Tier-0 standing, account nonce and publicly committed profile. Source inclusion alone is not pass evidence; inspect exact-head job outcome.
- Additional evidence required: exact-head clean-clone operational replay on an independent PC, cross-machine node/observer state-root verification, Cloudflare-hosted HTTPS binding, and multi-validator BFT/finality. The same-node restart step does not establish these.
- PR #81/#82/#88 and all semantic-review, Backend CI, P1, Reviewer Readiness, ballot privacy and locked-economic gates remain DRAFT / NO-GO.

## Reproducible safety contracts

```sh
cd web
npm ci
npm run test:tx-apply-receipt-truth
npm run test:tx-reconciliation-truth
npm run typecheck
npm run build
```

The full real-browser test also requires a locally running and actually producing controlled-devnet backend; see the scoped GitHub Actions workflow. **Do not** run against production credentials, remove existing devnet state or publish recovery files as debugging artifacts.

## First live-gate findings and remediation (2026-11-14)

- Initial real controlled-devnet test ran through signed Tier-0 registration with successful canonical receipt, then revealed an outdated **test assertion**: browser ML-DSA-65 public keys are encoded as base64, while the authoritative backend normalizes the same 1,952 bytes to lowercase hex (source: `weall.crypto.account_keys.canonical_account_key_pubkey`). The E2E now compares decoded bytes and validates the single canonical authority record rather than changing consensus encoding.
- A later full-browser run reached successful recovery on a second browser profile, then exposed an ambiguous text locator for `Edit public profile` (both tab button and summary). The E2E now targets the accessible owner-only tab explicitly; it does not weaken the signed profile action.
- **Exact-head first complete real-browser pass:** at commit `c75845c16e4670ddb1ffb36ea3c852bd2709a4fe`, the controlled-devnet browser suite passed all 2 tests, including recovery, successful committed profile update and unauthenticated third-browser observation (run `43639637760`). Web CI and Secrets Guard passed separately at this head. Backend CI, Focused P1 and Reviewer Readiness remained failing and cannot be waived.
- The stronger same-node restart/persistence gate was added **after** that passing run. It is not yet proven until its own exact-head run completes.
