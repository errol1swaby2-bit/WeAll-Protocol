#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${WEALL_DOCKER_GENESIS_COMPOSE_FILE:-docker-compose.genesis.yml}"
API_BASE="${WEALL_GENESIS_API_BASE:-http://127.0.0.1:8000}"
READINESS_URL="${API_BASE%/}/v1/genesis/observer/readiness"
TX_STATUS_URL="${API_BASE%/}/v1/tx/status/docker-genesis-boot-gate-nonexistent-tx"
PROJECT_NAME="${WEALL_DOCKER_GENESIS_PROJECT_NAME:-weall-genesis-api-boot-gate}"
SKIP_CLEANUP="${WEALL_DOCKER_GENESIS_KEEP_RUNNING:-0}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker_genesis_boot_gate: docker command not found" >&2
  exit 127
fi

cleanup() {
  if [ "$SKIP_CLEANUP" != "1" ]; then
    docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[docker-genesis-boot-gate] clean stale containers and volumes"
docker rm -f weall_api weall_producer >/dev/null 2>&1 || true
docker compose -p weall-genesis-api-boot-gate -f docker-compose.genesis.yml down -v --remove-orphans >/dev/null 2>&1 || true
docker volume ls --format '{{.Name}}' | grep -E 'weall.*genesis.*data|genesis-api-boot-gate.*weall-genesis-data' | xargs -r docker volume rm >/dev/null 2>&1 || true

echo "[docker-genesis-boot-gate] render compose"
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" config >/tmp/weall-docker-genesis-api-boot-gate.yml

echo "[docker-genesis-boot-gate] start Genesis API"
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up --build -d weall-api

echo "[docker-genesis-boot-gate] wait for readiness: $READINESS_URL"
python3 - "$READINESS_URL" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

url = sys.argv[1]
last_error = ""
for _ in range(60):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("readiness payload is not an object")
        if not payload.get("ok"):
            raise RuntimeError("readiness payload ok=false: " + json.dumps(payload, sort_keys=True))
        stage = str(payload.get("stage") or payload.get("readiness_stage") or "")
        if stage and stage != "first_trusted_external_observer_rehearsal":
            raise RuntimeError(f"unexpected readiness stage: {stage!r}")
        print("OK: Docker Genesis API observer readiness", json.dumps(payload, sort_keys=True))
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - gate prints actionable last error
        last_error = str(exc)
        time.sleep(1)
print("docker_genesis_boot_gate_failed: " + last_error, file=sys.stderr)
sys.exit(1)
PY

echo "[docker-genesis-boot-gate] verify tx-status read-only safety: $TX_STATUS_URL"
python3 - "$TX_STATUS_URL" <<'PYTXSTATUS'
import json
import sys
import time
import urllib.request

url = sys.argv[1]
last_error = ""
for _ in range(30):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("tx status payload is not an object")
        if payload.get("ok") is not True or str(payload.get("status") or "") != "unknown":
            raise RuntimeError("unexpected tx status payload: " + json.dumps(payload, sort_keys=True))
        print("OK: Docker Genesis API tx-status read-only safety", json.dumps(payload, sort_keys=True))
        sys.exit(0)
    except Exception as exc:
        last_error = str(exc)
        time.sleep(1)
print("docker_genesis_tx_status_gate_failed: " + last_error, file=sys.stderr)
sys.exit(1)
PYTXSTATUS

echo "[docker-genesis-boot-gate] OK"
