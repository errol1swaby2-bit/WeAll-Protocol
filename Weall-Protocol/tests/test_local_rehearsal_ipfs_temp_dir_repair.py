from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_local_rehearsal_prepares_ipfs_block_temp_directory() -> None:
    src = _script()

    assert "_prepare_local_ipfs_repo_dirs" in src
    assert '"${IPFS_PARTITION_PATH}/blocks"' in src
    assert '"${IPFS_PARTITION_PATH}/blocks/temp"' in src
    assert "failed to create batch temp directory" in src


def test_local_rehearsal_restart_stale_compose_ipfs_before_reset() -> None:
    src = _script()

    reset_index = src.index('if _bool_true "${RESET}"; then')
    reset_block = src[reset_index : src.index("_start_local_ipfs_daemon", reset_index)]
    assert "_stop_local_ipfs_daemon" in src
    assert 'docker compose -f "${IPFS_COMPOSE_FILE}" rm -sf "${IPFS_SERVICE}"' in src
    assert reset_block.index("_stop_local_ipfs_daemon") < reset_block.index(
        "scripts/devnet_reset_state.sh"
    )


def test_local_rehearsal_ipfs_ready_requires_add_healthcheck() -> None:
    src = _script()

    assert "_ipfs_add_healthcheck" in src
    assert "/api/v0/add?pin=false&wrap-with-directory=false&progress=false" in src
    assert "IPFS daemon already reachable and add-healthy" in src
    assert "reachable but add-unhealthy; restarting" in src
    assert "IPFS daemon ready and add-healthy" in src


def test_docker_partition_preflight_does_not_modify_container_owned_internals(tmp_path) -> None:
    src = _script()
    start = src.index("_prepare_local_ipfs_repo_dirs() {")
    end = src.index("_repair_docker_ipfs_batch_dir() {", start)
    devnet = tmp_path / ".weall-devnet"
    blocks = devnet / "ipfs_partition" / "blocks"
    blocks.mkdir(parents=True)
    (blocks / "SHARDING").write_text("sharded", encoding="utf-8")
    compose = tmp_path / "compose.yml"
    compose.touch()
    command = (
        "set -euo pipefail\n"
        'DEVNET_DIR="$1"; IPFS_PARTITION_PATH="$1/ipfs_partition"; IPFS_COMPOSE_FILE="$2"\n'
        # Simulate the Docker branch without running Docker or touching a real repo.
        "docker() { return 0; }\n" + src[start:end] + "\n_prepare_local_ipfs_repo_dirs\n"
    )
    result = subprocess.run(
        ["bash", "-c", command, "fixture", str(devnet), str(compose)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not (blocks / "temp").exists()


def test_docker_batch_repair_is_unprivileged_and_requires_failed_real_add() -> None:
    src = _script()
    start = src.index("_repair_docker_ipfs_batch_dir() {")
    end = src.index("_ipfs_add_healthcheck() {", start)
    repair = src[start:end]
    assert 'check-ipfs "${DEVNET_DIR}" "${IPFS_PARTITION_PATH}"' in repair
    assert 'exec -T --user ipfs "${IPFS_SERVICE}"' in repair
    assert 'test "$(id -u)" != 0' in repair
    assert 'test ! -L "$path"' in repair
    assert "test -f /data/ipfs/blocks/SHARDING" in repair
    assert "mkdir -p /data/ipfs/blocks/temp" in repair
    assert "test -w /data/ipfs/blocks/temp" in repair
    assert "rm -rf" not in repair
    assert "chmod " not in repair.replace("recursive chmod/chown", "")
    assert "! _repair_docker_ipfs_batch_dir || ! _ipfs_add_healthcheck" in src
