# WeAll Protocol — Production Operator Runbook (Genesis posture)

This runbook targets the **Genesis posture** launch:

- Single persistent chain from genesis
- Economics disabled by protocol lock (90 days)
- No unsigned txs
- Production hardening defaults

The node persistence layer is **SQLite-backed**. The authoritative on-disk state is:

- `./data/weall.db` (plus WAL side files `weall.db-wal` and `weall.db-shm` when WAL mode is enabled)

## Recommended deployment model

**Minimum (single host):**

- Run `weall-api` + `weall-producer` via Docker Compose
- API binds to `127.0.0.1:8000`
- A reverse proxy (Caddy/Nginx/Cloudflare Tunnel) terminates TLS and exposes public endpoints

Avoid exposing the raw container port directly to the internet.

## Requirements

- Docker + Docker Compose
- Disk space for `data/` (grows over time)
- Reverse proxy (recommended) if you want public access

## Install / start

From `projects/Weall-Protocol/`:

```bash
cp .env.prod.example .env.prod
# edit .env.prod (at minimum set WEALL_CHAIN_ID and node IDs)

docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
Health checks
bash
Copy code
curl -s http://127.0.0.1:8000/health | head
curl -s http://127.0.0.1:8000/v1/state/snapshot | head
If health fails:

bash
Copy code
docker logs weall_api --tail=200
docker logs weall_producer --tail=200
Persistence and backups
What to back up
SQLite runs in WAL mode. For a consistent offline backup, copy:

./data/weall.db

./data/weall.db-wal (if present)

./data/weall.db-shm (if present)

If you only copy weall.db while the node is live, you can end up with an incomplete snapshot.

Minimum backup strategy
Daily backup of data/ to offline storage

Keep at least:

last 7 daily backups

last 4 weekly backups

Safe backup procedure (single host)
For the safest snapshot, stop services briefly:

bash
Copy code
docker compose -f docker-compose.prod.yml --env-file .env.prod down

tar -czf weall-backup-$(date +%F).tgz data/

docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
If you need “no downtime” backups later, add a controlled SQLite checkpoint/backup command to node tooling.

Reverse proxy notes (TLS + edge protections)
Recommended proxy responsibilities:

TLS termination

Request rate limiting (edge)

Request size limits

Basic abuse protections (timeouts, header limits, WAF rules if desired)

This protocol stance avoids privileged “admin routes”; authorization should come from
PoH tier/session gating and protocol rules, not server-side superusers.

Genesis posture checklist
In .env.prod / compose:

WEALL_MODE=genesis

WEALL_ALLOW_UNSIGNED_TXS=0

WEALL_CHAIN_ID=... (your chosen chain id)

WEALL_DB_PATH=./data/weall.db

API port bind is 127.0.0.1:8000 (default in compose)

IPFS posture checklist
Defaults used in Genesis posture:

WEALL_IPFS_PIN_ON_UPLOAD=0

WEALL_MEDIA_AUTO_PIN_REQUEST=1

WEALL_IPFS_ENABLE_HEAL=1

WEALL_IPFS_HEAL_INTERVAL_BLOCKS=10

Meaning:

Uploading does not imply durable storage on the API node

The protocol requests pinning from operators

The system self-heals replication shortfalls by requesting pins again

Upgrade process (safe default)
Take a backup of data/

Pull new code / unpack new release

Rebuild containers:

bash
Copy code
docker compose -f docker-compose.prod.yml --env-file .env.prod down
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
Verify health and that the ledger tip changes as expected.

Incident quick hits
Disk full
Symptoms: writes failing, producer stalls.

Fix: free disk space, restore from backup if needed, restart services.

SQLite corruption / startup refusal
The node fails closed if it detects an invalid schema version.

Immediate steps:

Stop services

Restore from latest known-good backup

Restart services
