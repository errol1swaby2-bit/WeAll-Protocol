# Native Proof-of-Humanity bootstrap limits

WeAll's primary human-verification path must be protocol-native. It must not require email, SMTP, DNS, Cloudflare, CAPTCHA, OAuth, KYC vendors, government ID, or inbox control.

## Current model

- Basic Account: account exists, no human verification yet.
- Verified Person: native async human review.
- Trusted Verified Person: native live juror-attested review.

Current canon includes native async and live PoH transaction families. The chain/backend remains the authority for case state, evidence commitments, juror assignment, reviews, finalization, and receipts.

## Bootstrap problem

Async review requires eligible reviewers. Live review requires live verified jurors. Therefore the first eligible reviewer set must come from an auditable bootstrap process. This is unavoidable for a new human-verification network.

## Required bootstrap constraints

Bootstrap grants must be:

- explicit in genesis/state or governance history,
- receipt-backed,
- limited to the minimum useful initial reviewer set,
- visible to external reviewers,
- transitional,
- revocable/suspendable through deterministic state,
- replaced by native async/live review as soon as there is enough native reviewer capacity.

## What this milestone should claim

This milestone may claim that WeAll has a protocol-native PoH architecture and implementation path that does not require centralized identity infrastructure for primary verification. It should not claim that the reviewer set is already fully decentralized unless a live network transcript proves it.
