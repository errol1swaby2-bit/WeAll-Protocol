from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _script() -> str:
    return (ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh").read_text(
        encoding="utf-8"
    )


def test_local_rehearsal_starts_ipfs_before_backends() -> None:
    src = _script()

    assert 'START_IPFS="${WEALL_LOCAL_REHEARSAL_START_IPFS:-1}"' in src
    assert '_start_local_ipfs_daemon' in src
    assert 'docker compose -f "${IPFS_COMPOSE_FILE}" up -d --remove-orphans "${IPFS_SERVICE}"' in src
    assert 'ipfs daemon --migrate=true' in src

    assert src.index('_start_local_ipfs_daemon') < src.index('python3 scripts/devnet_tx.py ensure-keyfile')
    assert src.index('_start_local_ipfs_daemon') < src.index('Booting genesis backend')
    assert src.index('_start_local_ipfs_daemon') < src.index('Booting observer backend')


def test_local_rehearsal_exports_ipfs_bases_to_upload_backends() -> None:
    src = _script()

    genesis_start = src.index('Booting genesis backend')
    genesis_boot = src[genesis_start : src.index('_wait_http', genesis_start)]

    observer_start = src.index('Booting observer backend')
    observer_boot = src[observer_start : src.index('_wait_http', observer_start)]

    for boot in (genesis_boot, observer_boot):
        assert 'WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1' in boot
        assert 'WEALL_IPFS_API_BASE="${IPFS_API_BASE}"' in boot
        assert 'WEALL_IPFS_GATEWAY_BASE="${IPFS_GATEWAY_BASE}"' in boot


def test_local_rehearsal_surfaces_ipfs_endpoints_in_ready_output() -> None:
    src = _script()

    assert 'ipfs_api=${IPFS_API_BASE}' in src
    assert 'ipfs_gateway=${IPFS_GATEWAY_BASE}' in src
    assert 'IPFS daemon is required for PoH async video evidence uploads' in src
