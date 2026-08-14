from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SRC = ROOT / "src"


def _env_without_api_runtime_boot() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WEALL_API_BOOT_RUNTIME", None)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SRC), str(SCRIPTS), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    return env


def test_offline_api_rehearsal_imports_do_not_boot_repo_local_runtime(tmp_path: Path) -> None:
    code = (
        "import rehearse_api_driven_full_lifecycle_v1_5\n"
        "import rehearse_fully_api_driven_v15_lifecycle\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=_env_without_api_runtime_boot(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (tmp_path / "data").exists()


def test_full_node_rehearsal_child_disables_module_level_runtime_boot(tmp_path: Path) -> None:
    state_file = tmp_path / "node-state.json"
    code = "\n".join(
        [
            "from pathlib import Path",
            "import uvicorn",
            "import rehearse_full_node_process_controlled_validator_v1_5 as r",
            "uvicorn.run = lambda *args, **kwargs: None",
            f"raise SystemExit(r._node_app_main(0, Path({str(state_file)!r}), 'validator-a', 'validator'))",
        ]
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=_env_without_api_runtime_boot(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert state_file.exists()
    assert not (tmp_path / "data").exists()
