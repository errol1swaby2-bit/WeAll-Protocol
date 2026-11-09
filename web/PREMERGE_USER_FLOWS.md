# F1–F4 pre-merge user journeys and remote-access truth

Status: **design/implementation checklist**, not a claim of public network readiness,
PoH acceptance, consensus finality, or permission to merge PR #82.

This document describes the intended first-use and recovery journeys. Do not
make a browser button imply that a local key, signed request, pending receipt,
or accepted upload is an on-chain final outcome.

## Two distinct ways to participate

- **Browser account user:** uses a trusted HTTPS WeAll API access node.
  This does **not** make their phone/browser a full node, validator, operator,
  or separate consensus witness. Existing local cryptographic custody and
  recovery protections must hold in this mode.
- **Independent node operator:** runs, stores and independently verifies a
  WeAll node, configures upstream and identity, and passes a separate node
  operator rehearsal. Static website hosting alone cannot perform this.

## Public browser onboarding (progressively disclosed)

| Stage | User-facing question and action | Canonical proof boundary |
| --- | --- | --- |
| Connect | Which network and compatible node am I using? | Healthy HTTPS API, expected chain/genesis/tx-index/profile; trusted seed only when independently authorized |
| Account key | Do I want to create a new handle or restore an existing one? | Locally generated or cryptographically matched ML-DSA key, **not** a chain account |
| Save recovery | Where will I safely keep the backup? | Download/copy success reported locally; no network submission |
| Verify recovery | Can I actually restore this key? | Local key-match check before enabling registration |
| Register | Has the network accepted and synchronized the signed request? | Durable predicted tx ID; canonical confirmed receipt **and** account state, or explicit pending/rejected/unknown |
| Basic verification | What proof is required to become a verified person? | Tier-1 native async case, private evidence commitment, review and real canonical result |
| Live verification | What additional proof unlocks trusted participation? | Tier-2 live case and independent review, not mere room creation or camera permission |
| Participate | What can I read, post, vote or volunteer to review? | Canonical tier, reputation, standing and any separate role authority |

Each stage must have a clear back/continue path, its own error and pending state,
and an explicit distinction between **stored locally**, **sent**,
**confirmed**, **verified**, **eligible**, and **authorized**. Hide optional
passkey and advanced transaction details until their prerequisites are met.
Never automatically retry an ambiguous signed submission.

### Required failure and accessibility journeys

1. No compatible node, offline API, invalid certificate, rejected CORS, unsigned
   public registry: show **network unavailable**, safe retry, and no public
   membership claim. A browser must never silently fall back to arbitrary
   node endpoints or dev/bootstrap secrets.
2. Browser/mobile without camera, microphone or WebRTC: explain the unavailable
   verification stage without granting a tier; preserve basic account status.
3. Lost browser session but saved recovery: re-validate the registered account
   identity and local key, then use the canonical session mechanism.
4. Unknown registration receipt or node switching while pending: preserve
   transaction identity; do not re-dispatch a signed transaction or imply that
   switching proves state synchronization.
5. Observer behind, restarted or with mismatched commitments: distinguish
   pending, unavailable and rejected; do not mark an account synchronized
   merely because an API request succeeded.
6. Test user without their own PC: allow **browser API participation** only
   when an externally operated HTTPS node is legitimately available. This
   does not satisfy any protocol rule that explicitly requires a person's
   own independent full node or a distinct PoH reviewer.

## F2 bounded UI implementation — subject to exact-head CI

PR #82 now stages the Tier-1 async process into six separately visible
steps: understand → prepare → record → review/consent → encrypted submit →
canonical track. Native camera recording and the existing signed
`POH_ASYNC_REQUEST_OPEN`, `POH_ASYNC_EVIDENCE_DECLARE`, and
`POH_ASYNC_EVIDENCE_BIND` paths remain the authority sources. A successful
encrypted upload switches to **track**, not **verified**; pending/unknown
signed operations are not automatically resubmitted.

For Tier-2 live review, the visible steps are understand → request →
track/open a visible case. The existing live room remains a separate route;
only an authoritative tier update is shown as completed verification.
Keyboard transitions restore focus to newly displayed stage headings, and
Tier-2 service-role controls are folded away until eligible.

The history fetch now distinguishes a canonical empty case list from an
unavailable/malformed response. If either async or live case history cannot
be verified, the relevant new signed request is disabled and the UI presents
the history as **unknown**, never zero. Previously loaded cases can remain
visible but are explicitly stale until a successful refresh.

The repeated real-backend browser custody journey also includes a bounded
F2 subject-side check: a newly registered Tier-0 account enters the guided
verification page, must complete text preparation before reaching recording,
and cannot reach signed submission without a valid recorded video and consent.
It deliberately does **not** use fake camera footage or certify real PoH.

### Interrupted submission recovery — bounded implementation

A new account-scoped, non-secret browser journal is written **before**
sending an async evidence upload or a live signed request. It records only
the selected node API base, case type, progress phase, known case ID and
known canonical transaction ID. It never stores raw video, evidence encryption
keys, challenge phrases, response texts, encrypted evidence bytes, bearer
tokens or reviewer envelopes. If local storage cannot be read/written or
a previous request remains unresolved, further signed PoH requests fail closed.

After a browser reload the subject is guided to the **track** stage rather
than to a new submission. The warning survives a failed, empty or lagging
case-list read. A request is considered reconciled only if a successful
canonical case-history response from the **same configured node** contains
the exact recorded case ID. That merely proves a case is visible on the
chosen node; it does **not** prove reviewer eligibility, finality,
independence or an approved PoH tier. Lost-acknowledgment windows with no
available case ID still require operator-led investigation; there is no
automatic resend or unverified one-click local-journal clearing.

The new `test:poh-submission-journal` exercise tests malformed/denied
storage, same-case updates, wrong-node isolation and exact-case
reconciliation. The live repeated browser custody test additionally inserts
a **local-only negative marker** and reloads to prove a recorded
interruption cannot silently turn an empty case history into permission
for another signed request. It does not create a fictitious PoH case.

The async/live progress indicators now share a read-only `PohStepProgress`
component with active-step announcements and a marked current step.

The verification screen's read-only history and advanced technical
records are extracted into `VerificationHistoryPanel`, and role eligibility
display into `TrustedResponsibilitiesPanel`. The existing parent continues
to own canonical signed transactions and status refresh. A failed async or
live history read now shows **unavailable** in the history panel rather than
an incorrect empty-state message; an actual empty history appears only after
both categories return successful reads. Advanced API payloads remain
collapsed by default. Focused tests verify no signer, session or local
authority mutation was introduced in the read-only component.

These are **presentation and regression-test increments**, not completed
public PoH. The current `AccountVerificationPage.tsx` still contains too
much business logic and requires component/route extraction after source
and live-browser acceptance. Durable uncertain-case warning and no-resubmit gates are now implemented,
but complete authenticated receipt/nonce reconciliation and recoverable
interrupted upload continuation still require end-to-end acceptance. Manual tier override, fixture-only
success and replay-based signing shortcuts are prohibited.

## Remaining UX decompression before the combined PR

- Extract the now-larger account-verification page's async case creation,
  live room preparation, case history, and reviewer responsibilities into
  smaller bounded route components with independently visible progression.
- Present one primary next action per account tier, with read-only history
  separately accessible. Advanced JSON, debugging and operator details should
  not compete with a new user's verification action.
- Audit group join/approval, proposal creation/voting, and report/dispute
  journeys for separate **request / inclusion / authoritative result** phases.
- Keep a distinct 'run your own node' operator journey. Never advertise an
  access-node browser as a consensus validator.
- Test narrow mobile viewport, keyboard-only controls, screen-reader status
  announcements, interrupted uploads, device loss, and a separate-device
  live PoH rehearsal. Keep every unsupported path explicit and fail closed.

## Current launch limitation

The checked-in testnet seed registry has an empty signature and requires
rotation/re-signing. The optional HTTPS static-page package in PR #78 is a static
browser entry point; it cannot authorize genesis or make a node publicly
reachable. PR #82 itself does not include PR #78's separate node discovery
branch. Evaluate both against the eventual combined tree, not by pretending
either branch alone is a public network.

PR #82's saved recovery/verification, unavailable-node UX, and F2 guided
verification presentation are bounded implementation increments. Remaining
F2–F4 work is open until implemented and tested on exact commit evidence.
