# Cloudflare Optional Migration

Cloudflare is not required for WeAll Tier 1 PoH email verification.

The required path is:

```text
WeAll frontend → WeAll PoH email oracle → Stalwart SMTP → user inbox → email_control_attestation_v1 → chain verification
```

Cloudflare may exist only as an explicit optional adapter after the Stalwart/mock path passes.

## Acceptance checklist

- Tier 1 works with no Cloudflare Worker.
- Tier 1 works with no Cloudflare API token.
- Tier 1 works with no Cloudflare Email Routing.
- The chain verifies oracle signatures without Cloudflare.
- Devnet boots with Cloudflare env vars absent.
- Docs describe Cloudflare as optional only.
