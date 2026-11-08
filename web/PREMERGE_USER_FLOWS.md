# F1 pre-merge user journey decompression and remote-access truth

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
  operator rehearsal. Web hosting and Cloudflare alone cannot perform this.

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

## Remaining UX decompression before the combined PR

- Move the 80k-character account-verification page's async case creation,
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
rotation/re-signing. The HTTPS Cloudflare package in PR #78 is a static
browser entry point; it cannot authorize genesis or make a node publicly
reachable. PR #82 itself does not include PR #78's separate node discovery
branch. Evaluate both against the eventual combined tree, not by pretending
either branch alone is a public network.

PR #82's saved recovery/verification and unavailable-node UX are the first
bounded improvements in this checklist. All later work remains an open
acceptance task until implemented and tested on the exact PR head.
