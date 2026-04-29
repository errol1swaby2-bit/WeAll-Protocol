# PoH Email Oracle Operator Runbook

A PoH email oracle operator runs the WeAll PoH email oracle service plus Stalwart or another SMTP backend.

## Operator responsibilities

- Run `weall-poh-email-oracle`.
- Run Stalwart or another SMTP transport.
- Hold the oracle signing key securely.
- Register the oracle public key in the on-chain oracle registry.
- Monitor challenge, send, completion, and signing failures.

## Preflight

Run:

```bash
scripts/prod_oracle_env_check.sh
```

The preflight fails if the selected transport is incomplete or if the oracle signing key is missing.

## Normal node separation

Normal nodes do not need this setup. They verify attestations using chain state and the oracle registry.
