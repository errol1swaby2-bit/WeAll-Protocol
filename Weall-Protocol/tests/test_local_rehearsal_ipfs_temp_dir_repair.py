from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_local_rehearsal_prepares_ipfs_block_temp_directory_batch388() -> None:
    src = _script()

    assert "_prepare_local_ipfs_repo_dirs" in src
    assert '"${IPFS_PARTITION_PATH}/blocks"' in src
    assert '"${IPFS_PARTITION_PATH}/blocks/temp"' in src
    assert "failed to create batch temp directory" in src


def test_local_rehearsal_restart_stale_compose_ipfs_before_reset_batch388() -> None:
    src = _script()

    reset_index = src.index('if _bool_true "${RESET}"; then')
    reset_block = src[reset_index : src.index('_start_local_ipfs_daemon', reset_index)]
    assert "_stop_local_ipfs_daemon" in src
    assert 'docker compose -f "${IPFS_COMPOSE_FILE}" rm -sf "${IPFS_SERVICE}"' in src
    assert reset_block.index("_stop_local_ipfs_daemon") < reset_block.index("scripts/devnet_reset_state.sh")


def test_local_rehearsal_ipfs_ready_requires_add_healthcheck_batch388() -> None:
    src = _script()

    assert "_ipfs_add_healthcheck" in src
    assert "/api/v0/add?pin=false&wrap-with-directory=false&progress=false" in src
    assert "IPFS daemon already reachable and add-healthy" in src
    assert "reachable but add-unhealthy; restarting" in src
    assert "IPFS daemon ready and add-healthy" in src
