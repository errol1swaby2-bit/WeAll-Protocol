# Stalwart Mail Transport for PoH Email Oracle

Stalwart is the preferred self-hosted SMTP transport for WeAll Tier 1 email-control verification.

Stalwart is not an identity authority and must not hold oracle signing keys. It only sends mail for the oracle.

## Required operator DNS

Production mail domains should configure:

- MX record for the mail host.
- SPF allowing the Stalwart host to send for the domain.
- DKIM signing in Stalwart.
- DMARC policy.
- Reverse DNS for the sending IP where possible.
- TLS certificates for SMTP submission.

## Required oracle env

```bash
WEALL_EMAIL_TRANSPORT=stalwart_smtp
WEALL_SMTP_HOST=stalwart
WEALL_SMTP_PORT=587
WEALL_SMTP_USERNAME=verify@poh.weall.example
WEALL_SMTP_PASSWORD_FILE=/run/secrets/weall_smtp_password
WEALL_SMTP_FROM=verify@poh.weall.example
WEALL_EMAIL_ORACLE_ID=oracle:poh-email:operator-1
WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE=/run/secrets/weall_email_oracle_private_key
WEALL_EMAIL_ORACLE_PUBLIC_KEY=<registered oracle pubkey>
WEALL_NODE_RPC_URL=http://weall_api:8000
```

## Security warnings

- Do not expose the Stalwart admin API publicly.
- Do not store oracle private keys in Stalwart.
- Do not allow Stalwart to write chain state.
- Do not put raw mailbox data into protocol state.
- Keep SMTP logs redacted and outside public state snapshots.
