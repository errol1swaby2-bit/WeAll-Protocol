# Normal Node Operator Role

A normal WeAll node verifies chain state. It does not need to send email.

A normal node must not require:

- Cloudflare Worker deployment.
- Cloudflare API token.
- Cloudflare Email Routing.
- Stalwart.
- SMTP credentials.
- PoH email oracle private key.

Normal nodes verify `email_control_attestation_v1` through the on-chain oracle registry.
