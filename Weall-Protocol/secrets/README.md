# Secrets directory (DO NOT COMMIT KEYS)

This directory is intentionally **empty** in the repository.

Production deployments must inject secrets at runtime (Docker secrets, Vault/KMS, SOPS, etc.).
**Never commit or ship real keys/certs**.

---

## Expected secret filenames (local only)

These filenames are referenced by the production Docker Compose files. Place them here locally
(or mount them via Docker secrets) so containers can read them at runtime.

### Node identity keys (P2P identity / signing)
- `secrets/weall_node_privkey`
- `secrets/weall_node_pubkey`

**Notes**
- These are the node’s long-lived identity keys.
- Keep the private key strictly secret (permissions `0600`).

### Validator identity (if running a validator / producer role)
- `secrets/weall_validator_account`

**Notes**
- This is the validator account identifier used by the runtime for validator-specific actions.

### Network TLS (P2P transport TLS)
These are required by the production compose wiring for secure node-to-node transport:

- `secrets/weall_net_tls_cert.pem`  (PEM X.509 certificate)
- `secrets/weall_net_tls_key.pem`   (PEM private key)
- `secrets/weall_net_tls_ca.pem`    (PEM CA bundle / trust root)

**Notes**
- Use a real CA / proper issuance for real deployments.
- For development you may use a self-signed CA and issue node certs from it.
- Keep the TLS private key strictly secret (permissions `0600`).

---

## File permissions (recommended)
On Linux/WSL, ensure secrets are not world-readable:

```bash
chmod 600 secrets/weall_node_privkey secrets/weall_net_tls_key.pem
chmod 644 secrets/weall_node_pubkey secrets/weall_net_tls_cert.pem secrets/weall_net_tls_ca.pem secrets/weall_validator_account
