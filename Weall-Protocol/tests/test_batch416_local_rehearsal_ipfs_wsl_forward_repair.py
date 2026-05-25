from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_local_rehearsal_repairs_stale_docker_wsl_ipfs_forwards_batch416() -> None:
    src = _script()

    assert 'IPFS_PORT_REPAIR="${WEALL_LOCAL_REHEARSAL_IPFS_PORT_REPAIR:-1}"' in src
    assert 'IPFS_API_FALLBACK_PORT="${WEALL_LOCAL_REHEARSAL_IPFS_API_FALLBACK_PORT:-15001}"' in src
    assert 'IPFS_GATEWAY_FALLBACK_PORT="${WEALL_LOCAL_REHEARSAL_IPFS_GATEWAY_FALLBACK_PORT:-18080}"' in src
    assert "_repair_local_ipfs_ports" in src
    assert "_start_ipfs_with_docker_compose_repair" in src
    assert "_ipfs_compose_failure_looks_like_port_forward" in src
    assert "Docker Desktop/WSL" in src
    assert "stale localhost forward" in src
    assert "wsl --shutdown" in src


def test_local_rehearsal_exports_fallback_ipfs_ports_to_compose_batch416() -> None:
    src = _script()

    assert 'export WEALL_IPFS_API_PORT="${api_port}"' in src
    assert 'export WEALL_IPFS_GATEWAY_PORT="${gateway_port}"' in src
    assert 'export IPFS_API_PORT="${api_port}"' in src
    assert 'export IPFS_GATEWAY_PORT="${gateway_port}"' in src
    assert 'IPFS_API_BASE="$(_replace_url_port "${IPFS_API_BASE}" "${IPFS_API_FALLBACK_PORT}")"' in src
    assert 'IPFS_GATEWAY_BASE="$(_replace_url_port "${IPFS_GATEWAY_BASE}" "${IPFS_GATEWAY_FALLBACK_PORT}")"' in src


def test_local_rehearsal_still_preserves_existing_ipfs_contracts_batch416() -> None:
    src = _script()

    assert 'docker compose -f "${IPFS_COMPOSE_FILE}" up -d --remove-orphans "${IPFS_SERVICE}"' in src
    assert 'docker compose -f "${IPFS_COMPOSE_FILE}" rm -sf "${IPFS_SERVICE}"' in src
    assert 'docker compose -f "${IPFS_COMPOSE_FILE}" down --remove-orphans' in src
    assert 'WEALL_IPFS_GATEWAY_BASE="${IPFS_GATEWAY_BASE}"' in src
    assert 'ipfs_gateway=${IPFS_GATEWAY_BASE}' in src
