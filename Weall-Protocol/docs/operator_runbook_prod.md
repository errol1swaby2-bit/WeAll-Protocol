# WeAll Protocol — Production Operator Runbook

This runbook describes the current operator-facing posture for the WeAll Genesis node software.
It is intentionally conservative: the repository is production-candidate protocol software, but public mainnet deployment still requires a final fresh-clone operator rehearsal, public-validator beta review, and external security review.

## 1. Launch postures

### Genesis bootstrap posture

Genesis bootstrap is the controlled chain-initialization posture:

- single persistent chain from genesis
- economics disabled by the protocol lock for the Genesis Constitutional Phase
- no unsigned public txs
- production hardening defaults
- bootstrap authority limited to documented genesis/operator tooling

Genesis compose files may use `WEALL_MODE=genesis` for this controlled launch path.

### Production validator/service posture

Public validator or service operation must use production mode:

```text
WEALL_MODE=prod
WEALL_BFT_ENABLED=1
WEALL_VALIDATOR_SIGNING_ENABLED=1   # only for actual validator signers
```

A node must not mix observer mode with validator signing, and validator/service signing must fail closed unless HotStuff/BFT is enabled and effective.

## 2. Required preflight checks

From `Weall-Protocol/` before packaging or deploying:

```bash
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh
```

Expected current checkpoint:

```text
tx canon: 230 tx types, version 1.25.0
latest full backend suite: 2789 passed, 1 warning
backend locks: requirements.lock, requirements-dev.lock
frontend lock: ../web/package-lock.json
```

## 3. Dependency and frontend verification

Backend locks must be present, pinned, and hashed:

```bash
bash scripts/verify_lockfiles.sh
bash scripts/verify_release_dependencies.sh
```

Frontend verification requires a running backend for the contract check:

```bash
cd ../web
npm ci
API_BASE=http://127.0.0.1:8000 npm run contract-check
npm run typecheck
npm run build
```

## 4. Recommended deployment model

Minimum single-host model:

- run `weall-api` and producer services via Docker Compose
- bind the API to `127.0.0.1:8000`
- expose public endpoints through a reverse proxy such as Caddy, Nginx, or a tunnel provider
- terminate TLS at the proxy
- enforce request size/time/rate limits at the edge

Avoid exposing the raw container port directly to the internet.

## 5. Persistence and backups

The default node persistence layer is SQLite-backed. The authoritative on-disk state is:

```text
./data/weall.db
./data/weall.db-wal   # when WAL mode is enabled
./data/weall.db-shm   # when WAL mode is enabled
```

If you copy only `weall.db` while the node is live, the snapshot can be incomplete.

Safe offline backup procedure:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod down
tar -czf weall-backup-$(date +%F).tgz data/
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
```

Recommended retention:

- last 7 daily backups
- last 4 weekly backups
- manual backup before every upgrade

## 6. Health checks

With the API bound locally:

```bash
curl -s http://127.0.0.1:8000/v1/readyz | head
curl -s http://127.0.0.1:8000/v1/status | head
curl -s http://127.0.0.1:8000/v1/state/snapshot | head
```

If health fails:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod ps
docker logs weall_api --tail=200
docker logs weall_producer --tail=200
```

## 7. Consensus and authority invariants operators should know

Current production-candidate hardening includes:

- two-tier native PoH: async Tier 1 and live Tier 2
- no required email, Cloudflare, SMTP, DNS, CAPTCHA, OAuth, KYC provider, or government ID provider for PoH authority
- adaptive Live PoH quorum: up to 10 jurors, up to 3 active reviewers, up to 7 watchers
- follower-side SYSTEM tx replay binding to deterministic scheduler output before apply
- helper execution metadata committed through `helper_execution_root` when present
- BFT-required public validator signing posture
- dependency lockfiles for backend and frontend packaging

## 8. IPFS/media posture

Default Genesis posture:

```text
WEALL_IPFS_PIN_ON_UPLOAD=0
WEALL_MEDIA_AUTO_PIN_REQUEST=1
WEALL_IPFS_ENABLE_HEAL=1
WEALL_IPFS_HEAL_INTERVAL_BLOCKS=10
```

Meaning:

- upload does not automatically imply durable storage on the API node
- the protocol requests pinning from storage operators
- replication shortfalls can be re-requested by the healing flow

## 9. Upgrade process

Safe default:

1. Take a backup of `data/`.
2. Pull the new code or unpack the new release.
3. Re-run release checks.
4. Rebuild and restart containers.
5. Verify health and ledger progress.

```bash
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh

docker compose -f docker-compose.prod.yml --env-file .env.prod down
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

## 10. Incident quick hits

### Disk full

Symptoms: writes fail, producer stalls, health degrades.

Immediate actions:

1. Stop services.
2. Free disk space or expand the volume.
3. Restart services.
4. Verify `/v1/readyz` and `/v1/status`.

### SQLite corruption or schema refusal

Immediate actions:

1. Stop services.
2. Preserve the failed `data/` directory for forensic review.
3. Restore the latest known-good backup.
4. Restart services.
5. Verify ledger height and state root against the expected operator record.

## 11. What is not claimed yet

This runbook does not claim public mainnet readiness. Before public production launch, the project still needs:

- fresh-clone operator rehearsal on a clean host
- public-validator beta drill
- multi-node launch rehearsal
- external security review
- final incident-response and operator documentation review
