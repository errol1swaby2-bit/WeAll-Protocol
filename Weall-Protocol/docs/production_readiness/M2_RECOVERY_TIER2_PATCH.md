# Milestone 2 complete-objectives implementation patch

## Scope

This patch addresses the code, test, runbook, and closure-harness work identified by the Milestone 2 pre-push audit. It replaces the earlier recovery/Tier-2 foundation posture with a complete implementation candidate for the human-account custody, recovery, Proof-of-Humanity, evidence-lifecycle, reviewer, and outside-tester objectives.

Milestone 2 is **not closed merely because this patch applies**. Closure additionally requires:

1. An operator-signed replacement public-testnet seed registry bound to the regenerated chain identity.
2. A clean implementation-freeze commit.
3. A successful run of `scripts/run_m2_complete_closure.sh` in the maintainer WSL environment.
4. A direct child evidence-only commit containing the generated `artifacts/m2-closure/**` transcripts and manifest.

## Implemented P0 security and correctness behavior

- Ordinary active account authority cannot rotate an already registered offline recovery authority.
- New v2 registrations require an independent offline ML-DSA recovery key and ML-KEM evidence-encryption key.
- Recovery replacement keys must be fresh and independent from all current and prior account/recovery authority.
- A prior active key cannot cancel an independently authorized offline, continuity, or reversal recovery.
- Failed recovery decisions are recorded canonically and enforced through the rolling failure window and cooldown policy.
- Guardian recovery is disabled in the regenerated production and public-testnet genesis states. Historical replay behavior remains interpretable.
- PoH and continuity/reversal evidence is encrypted before provider upload and bound to exact ciphertext bytes.
- Full recipient key envelopes are available only to an authenticated subject or chain-accepted reviewer while the case remains open.
- Reviewer envelope access is removed when the case closes and evidence enters sealed retention.
- The account-private-key persistence source regression is corrected and covered by source tests.

## Implemented P1 lifecycle behavior

### Account recovery

The canonical recovery methods are:

- `offline_key`: authorization by the currently registered purpose-limited offline recovery authority.
- `continuity`: two independent evidence classes, at least one strong continuity anchor, a deterministic 15-reviewer panel, and 10 approvals.
- `reversal`: a challenge during the recovery restriction window using a fresh 25-reviewer panel, excluding prior recovery reviewers, and requiring 20 approvals.

Successful finalization atomically:

1. Revalidates the request and authority generation.
2. Revokes all prior account authority keys.
3. Revokes all registered devices and active sessions.
4. Installs one fresh replacement account authority.
5. Installs one fresh independent offline recovery authority.
6. Starts or extends the 8,640-block high-risk restriction.
7. Seals case evidence and removes reviewer key envelopes.
8. Emits a public recovery or reversal receipt and incident history.

### Encrypted evidence lifecycle

Every registered evidence object follows a deterministic lifecycle:

```text
uploaded
→ reviewer_accessible
→ sealed_retention
→ deletion_due
→ erasure_pending
→ erased
```

The lifecycle records the retention due height, the 4,320-block deletion-completion deadline, 180-block retries, deadline-missed receipts, provider deletion attestations, key-erasure commitments, and the final erasure receipt. Provider attestations must be signed by a provider recorded for that evidence object.

The controlled local encrypted-object store used by browser E2E is non-production infrastructure. Production deployments must use an accountable provider integration and complete its deletion attestations.

### Async and live PoH

- Declined async reviewers are deterministically replaced.
- Follow-up reviews open a new canonical follow-up round in which the applicant may bind new encrypted evidence and reviewers must review the current round.
- Browser E2E actors use independent browser contexts and authenticated session keys.
- The async browser journey performs an actual AES-GCM encryption, provider upload, per-recipient ML-KEM wrapping, reviewer-side decryption, follow-up review, finalization, and Tier 1 observation.
- The live browser journey uses separate applicant/reviewer contexts, fake CI camera/microphone transport, chain-committed acceptance and attendance, UI-submitted verdicts, Tier 2 finalization, and a Tier-2-gated action.
- WebRTC remains non-authoritative transport; only signed canonical attendance and verdict transactions affect civic status.

### Tier 2 lifecycle

- Tier 2 is valid for exactly 777,600 finalized blocks.
- Five canonical reminder receipts are emitted.
- A real reverification case is opened at the configured boundary.
- Expiration is processed before user transactions at the first later height and falls back to Tier 1.
- Existing frozen electorates remain unchanged.
- Tier-2-only assignments stop accepting new work and enter deterministic replacement or bounded safe-withdrawal state.

### Account gates and institutional identity

The account-tier gates are corrected so designated low-risk public discussion and reaction actions are available at Tier 0, while Tier 1 may perform the specification-authorized flag/dispute actions. Higher-authority governance and responsibility actions remain Tier 2 gated.

Institutional identity is formally removed from the Milestone 2 closure boundary by `docs/architecture/ADR-M2-INSTITUTIONAL-IDENTITY-RESCOPE.md`. No M2 claim includes institutional formation or representative authority.

## Pinned chain and seed-registry boundary

The production and public-testnet genesis ledgers, manifests, trust roots, transaction-index commitments, and chain commitments are regenerated for the new v2 account requirements and guardian retirement.

The repository intentionally marks the checked-in seed registry as `rotation_required`. The private signing authority is not stored in the repository and cannot be manufactured by a patch. Before closure, the operator must run:

```bash
cd Weall-Protocol
read -rsp "Seed-registry ML-DSA private key: " WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY
printf "\n"
bash scripts/rotate_public_testnet_seed_registry_m2.sh
unset WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY
PYTHONPATH=src python3 scripts/check_public_testnet_seed_registry_rotation.py
```

The strict closure runner fails until that signed registry validates against the regenerated chain commitments.

## Required closure

After applying, reviewing, and committing this patch as the implementation freeze:

```bash
export M2_IMPLEMENTATION_FREEZE_COMMIT="$(git rev-parse HEAD)"
bash scripts/run_m2_complete_closure.sh
```

The runner executes the complete backend suite, generated-artifact checks, frontend typecheck/build/safety gates, mandatory custody/async/live browser journeys, media rehearsal, restart/replay, two-node state-root equality, observer catch-up, artifact sanitization, and evidence-manifest generation.

Then stage only `artifacts/m2-closure/**` and validate:

```bash
M2_IMPLEMENTATION_FREEZE_COMMIT="$M2_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m2_evidence_only_commit.sh --cached
```

The evidence-only commit must be the direct child of the implementation-freeze commit. No source, config, test, or specification file may change in that commit.
