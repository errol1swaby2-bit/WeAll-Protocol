# PR #93 — F-001: observer automatic authentication

**Status: OPEN — candidate remediation, not acceptance evidence.** Manual clean-clone rehearsal on November 18, 2026 at efe4e358ecd2a4a887a39987213d1f70481fa0e3.

## Observed evidence

- README launcher reported both frontends and backends reachable (5173/5174, 8001/8002), with observer manifest and bootstrap-secret route returning 200. No credentials were copied into evidence.
- Login POST returned 403 with `direct_session_mutation_forbidden_in_controlled_devnet`. That denial is correct and must remain.
- Observer transaction queue had 31 records: one account registration, 15 device registrations, 15 session issues, all marked upstream-confirmed and locally synchronized.
- One device receipt was independently retrieved from both nodes at height 136 with the same block ID, apply_ok=true and local_state_synced=true. Its queue creation-to-last-update span was about 291 seconds, not a measured confirmation latency.
- Latest issued candidate was authenticated=true, active=true, expired=false when checked on both node APIs without printing the bearer. Chrome Network filter showed zero session/me calls out of 486 recorded requests. The frontend did not reach its final authorization check during the observed capture.
- This establishes an authentication/retry failure and redundant ledger actions, not a demonstrated exact timing root cause. HTTP admission, a nonce, or a confirmed queue record is not by itself authorization.

## Candidate remediation

Preserve an exact pre-dispatch transaction ID and nonce for both device registration and session issuance, plus the candidate bearer, in a **tab-scoped** journal. Same-tab reload or retry reconciles that attempt, never signs another tracked action. Acknowledgement mismatches block recovery. The private journal is not placed in localStorage and does not make a pending bearer active. Both device and session receipts require successful canonical apply and observer synchronization, followed by the existing nonce and session/me authorization gates. Bounded polling is extended to 120 seconds per stage; controlled-demo bootstrap can continue the same attempt on pending receipt/authorization, rather than conceal failure or create fresh credentials. Successful bootstrap markers follow authenticated establishment; restored signer alone is not authenticated. Direct mutation policy and backend unchanged.

The journal deliberately does not survive tab closure as a guaranteed persistence boundary; no raw bearer or signing seed is moved to durable browser storage. A definitively rejected or ambiguous never-admitted tracked identity is not silently replaced, and operational recovery/explicit abandon with revocation is still a separate UX question. No cross-tab global one-session guarantee or production BFT finality is claimed. The original contaminated test ledger remains diagnostic evidence; closing a tab does not revoke its previously issued sessions.

## Acceptance gates (not yet attested)

1. Focused actual frontend orchestration tests: pending receipt, interruption, same-tab reload, lost acknowledgement, account/chain scope, failed authorization, storage failure, acknowledgement mismatch, concurrent callers.
2. Real browser regression with the unmodified README launcher and actual two backends/two frontend origins. Intentional interruption drops only observer receipt GETs for more than the original 30s timeout and reloads the same tab. No forged result, session injection, or backend bypass. Assert gate denial, successful canonical receipt/authorization and one device/issue per actor, without leaking secrets. The fresh local demo accounts are fixture identities, not independent humans or public nodes.
3. Run all required exact-head gates, then repeat manual clean-clone test using the documented launcher. Preserve earlier evidence until deliberately reset by operator. No merge, public testnet, hosted frontend release or Genesis authority follows from this work.

## First CI attempt at de9faa75a91e4278c2afa28032bd881a37a318f7

- Typecheck and focused login-resume orchestration tests passed. Web functional/local deployment job and dependency security job passed.
- New real README browser workflow failed **before launcher readiness**, because the CI-provided custom runtime path used a leaf other than the required `.weall-devnet`. The path is now preflighted with the existing safety helper. Failure diagnostics emit only fixed stage categories, not raw launcher logs.
- Backend, A01–A20 P1, and Reviewer Readiness failed on the new unmapped authentication source module. It is now explicitly mapped to the same M-069 authoritative/launch-critical classification as session.ts. Strict generated evidence refresh remains required; no approval digests are changed.
- M4.1 reached the final independent-browser recovery sign-in and timed out waiting for home. Earlier new-account activation and profile stages completed. The exact recovery failure is unproven; add stage-count and redacted browser state diagnostics rather than weakening assertions or increasing the test deadline. The real-stack regression remains red until a subsequent exact-head pass.

## Second CI attempt at abed582d87cbe15af6977dde374d75db8c2b2fb8

- 40 of 44 PR-triggered workflows passed, including Web CI, M4.1 (independent account recovery completed on this attempt in the 19.2-second browser test), M4.2 and J01–J02. The earlier M4.1 timeout was not reproduced; its exact cause remains unknown.
- The runtime path preflight succeeded. F-001 failed after old-process cleanup but before either node booted. The recorded categories do not distinguish image pull, Compose startup, bind permissions, or daemon health; do not claim a diagnosis or browser result. Add a preflight for the exact pinned Compose image and targeted, credential-safe IPFS stage/exit diagnostics. Preserve actual launcher startup and health checks.
- The strict derivative refresh reconstructed the V2 artifacts, reproduced the clean archive, killed all 20 non-equivalent mutants and passed the semantic inventory checks. Its final verification refused publication because this audit document included a named hosting provider. Replace that incidental reference with provider-neutral wording; preserve the provider-independence test and approval records. Backend, P1 and Reviewer Readiness remain stale at the tested head until verified generated-only publication and exact-head revalidation.

## Third CI attempt and follow-up

- At 4cc9961c6ac901f3e22dd8ebb6adec3653e17d62 the launcher-pinned IPFS image was available, the container was running and its version API responded. The host post-initialization attempt to create the blockstore batch temp directory failed with a permission error. This is a separate Linux launcher portability defect, not evidence of a failed browser transaction. The candidate change preserves the host path checks, defers container-owned batch directory handling to the non-root Kubo user only if an actual add fails, and still requires a real successful add before boot. No ownership reset, privileged repair, or automatic deletion is introduced.
- M4.1 again timed out on independent recovery; redacted capture showed one direct-login 403, no dispatched canonical receipt, and the journal envelope mismatch. That is a pre-dispatch failure. The exact mismatching field was not logged. The signing helper previously fetched an unscoped cached chain ID or fallback despite the journal verifying the selected node independently. The candidate now binds a fresh selected-node chain check to signing for journaled actions and forbids automatic nonce reallocation for those tracked actions. Fixed field-level mismatch categories and focused tests distinguish remaining failure modes without exposing credentials. The chain-resolution defect is concrete; whether it caused the observed intermittent mismatch remains to be verified.
- The approved derivative refresh succeeded and published generated-only head 84bcb8339ca1c9c805196cc7a0f7d9195142cad6. All 44 PR checks at that head completed as action_required, with no jobs returned for the F-001 and Backend runs. The execution blocker is not a test result; its administrative reason is not visible through the available API. New candidate changes require fresh generated evidence and full execution when Actions is available.
