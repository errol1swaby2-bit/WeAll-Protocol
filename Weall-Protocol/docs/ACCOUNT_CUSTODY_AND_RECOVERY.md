# Account custody and recovery

WeAll account creation must protect normal users from losing access to an account they just created. The frontend therefore treats local key generation, recovery backup, easy sign-in, and on-chain account registration as separate steps.

## Required account creation ceremony

A new user account follows this sequence:

1. Choose a handle.
2. Generate the account key locally in the browser.
3. Download or copy the recovery file.
4. Verify the recovery file by uploading it back or pasting the recovery JSON.
5. Optionally add easy sign-in on this device.
6. Continue to account verification/onboarding.

The user cannot continue from the create-account flow until the saved recovery material is verified against the freshly generated account key. A manual checkbox is not sufficient.

## Recovery verification rule

The recovery file must be parsed and checked before the user can continue:

- account in the file must match the generated account;
- public key in the file must match the generated account public key;
- secret key in the file must derive and validate the same public key;
- when the current generated secret is available, the saved secret must match it exactly.

This proves the user has a working copy of the recovery material before a browser close, device reset, or session loss can make the account unrecoverable.

## Easy sign-in boundary

Easy sign-in is convenience only. It does not replace the verified recovery file. If easy sign-in recognizes an account but the local signer is missing, the frontend must send the user to the recovery flow instead of attempting writes.

## Storage boundary

Raw private key material must not be stored in persistent `localStorage`. Browser session metadata may be stored locally, but a protected write must still require a local signer. If the session remains while the signer is gone, the UI should show a recovery prompt instead of silently failing or creating a new account.

## User-facing language

The UI should distinguish:

- `Account key created locally` — a local key exists in this browser session.
- `Recovery verified` — the user has proven they saved a usable backup.
- `Account registered` — an on-chain account registration has confirmed.
- `Account verification` — the PoH/verification process can begin.

This avoids implying that a local key alone is the same as a durable registered WeAll account.
