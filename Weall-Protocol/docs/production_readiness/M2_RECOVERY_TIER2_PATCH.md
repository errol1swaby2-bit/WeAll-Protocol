# Milestone 2 Recovery and Tier-2 Lifecycle Patch

## Scope

This patch closes the consensus-critical foundation for Milestone 2 account recovery and Tier-2 expiration handling. It does not claim completion of continuity-panel recovery, recovery reversal, encrypted evidence deletion, or the complete async/live multi-browser tester journey.

Implemented behavior:

- Purpose-limited offline recovery keys can authorize only `ACCOUNT_RECOVERY_REQUEST` transactions.
- Offline recovery finalization atomically replaces account authority and rotates the offline recovery key.
- Finalization revokes prior account keys, devices, and session keys.
- Recovery starts an 8,640-finalized-block restriction window enforced in admission gates and again at apply time.
- A locked account retains a narrow ability to cancel its active recovery request.
- New states created by the v2 genesis bootstrap disable new guardian recovery admission while historical states without the selector remain replay-compatible.
- Authorized recovery requests are finalized and receipted by deterministic system transactions.
- Tier 2 receives an exact 777,600-block validity term.
- Tier-2 reminder heights, reverification opening, and expiry are processed deterministically before user transactions.
- Expired Tier 2 falls back to Tier 1 rather than Tier 0.
- Legacy account mirrors now reflect canonical PoH downgrades instead of preserving stale higher tiers.
- The browser custody journey has a mandatory real-stack launcher that fails when the backend is unavailable rather than silently skipping.

## Consensus boundaries

### Offline recovery authority

The configured offline key is stored outside the account's active key set. Signature verification selects it only when all of the following hold:

1. The transaction type is `ACCOUNT_RECOVERY_REQUEST`.
2. The payload method is `offline_key`.
3. The transaction signature profile matches the configured recovery-key profile.
4. The signature verifies against the configured recovery public key.

A recovery-key signature does not fall through to ordinary active-key authorization.

### Atomic replacement

`ACCOUNT_RECOVERY_FINALIZE` performs one state transition that:

1. Rechecks the recovery generation.
2. Revokes every previously active account key.
3. Installs the requested replacement authority key.
4. Revokes registered devices.
5. Revokes active session keys.
6. Rotates the offline recovery key and generation.
7. Starts the post-recovery restriction window.
8. Supersedes other open or approved recovery requests.
9. Synchronizes all legacy key mirrors.

### Post-recovery restriction

The restriction remains active through `restriction_until_height`. The default check evaluates the next candidate height. Only the explicit low-risk allowlist in `account_recovery_policy.py` remains available. Apply-time enforcement protects replay and block ingestion even when mempool admission is bypassed.

### Tier-2 expiration

A Tier-2 award remains effective through `expires_at_height`. At the first later block, the lifecycle processor records expiration before user transactions. Canonical historical status retains the prior Tier-2 award and marks it expired; effective standing and account mirrors become Tier 1.

## Chain-identity note

This patch does not rewrite the checked-in production or public-testnet genesis ledgers because doing so changes pinned genesis hashes and invalidates the currently signed public seed registry. The v2 bootstrap default disables new guardian admission for newly created states. A coordinated public-testnet reset must regenerate the ledger and manifest, update trust roots, and republish a newly signed seed registry in one controlled operation.

## Required validation

Run the targeted backend suite:

```bash
cd Weall-Protocol
python3 -m pytest -q \
  tests/test_identity_domain_mvp.py \
  tests/test_poh_async_safety.py \
  tests/test_poh_two_tier_hard_invariant.py \
  tests/test_poh_v2_two_tier_migration.py \
  tests/test_poh_eligibility_rules.py \
  tests/test_reviewer_safety.py \
  tests/test_m2_account_recovery_and_tier2_lifecycle.py
```

Run the mandatory custody journey:

```bash
bash scripts/run_account_custody_real_stack_e2e.sh
```

The real-stack launcher installs frontend dependencies when absent, starts an isolated backend, requires the real backend path, and preserves no runtime directory unless `WEALL_KEEP_M2_CUSTODY_RUNTIME=1` is set.

## Remaining Milestone 2 implementation

The following items require subsequent patches before the complete Milestone 2 list can be honestly closed:

- Tier-2 continuity-panel recovery with evidence-class and reviewer-conflict enforcement.
- Recovery reversal with a fresh 25-reviewer panel and 20-approval threshold.
- Canonical failure accounting for continuity recovery attempts.
- Responsibility replacement and safe withdrawal after Tier-2 expiration.
- Encrypted PoH evidence grants, closure-time revocation, retention, deletion retries, and provider attestations.
- Complete real-browser async Tier-1 and live Tier-2 journeys with independent actors.
- External reviewer/tester runbooks and multi-node evidence capture for those journeys.
- Coordinated chain-identity reset and signed registry republishing to retire guardian admission on the pinned public testnet.
