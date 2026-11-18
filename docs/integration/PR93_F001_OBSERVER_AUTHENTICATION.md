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
3. Run all required exact-head gates, then repeat manual clean-clone test using the documented launcher. Preserve earlier evidence until deliberately reset by operator. No merge, public testnet, Cloudflare release or Genesis authority follows from this work.

## First CI attempt at de9faa75a91e4278c2afa28032bd881a37a318f7

- Typecheck and focused login-resume orchestration tests passed. Web functional/local deployment job and dependency security job passed.
- New real README browser workflow failed **before launcher readiness**, because the CI-provided custom runtime path used a leaf other than the required `.weall-devnet`. The path is now preflighted with the existing safety helper. Failure diagnostics emit only fixed stage categories, not raw launcher logs.
- Backend, A01–A20 P1, and Reviewer Readiness failed on the new unmapped authentication source module. It is now explicitly mapped to the same M-069 authoritative/launch-critical classification as session.ts. Strict generated evidence refresh remains required; no approval digests are changed.
- M4.1 reached the final independent-browser recovery sign-in and timed out waiting for home. Earlier new-account activation and profile stages completed. The exact recovery failure is unproven; add stage-count and redacted browser state diagnostics rather than weakening assertions or increasing the test deadline. The real-stack regression remains red until a subsequent exact-head pass.
