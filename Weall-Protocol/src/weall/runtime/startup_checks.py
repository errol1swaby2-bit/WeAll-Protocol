import os

from weall.runtime.chain_config import validate_runtime_env


def validate_environment():
    required = [
        "WEALL_MODE",
    ]

    for r in required:
        if r not in os.environ:
            raise RuntimeError(f"Missing required env: {r}")

    validate_runtime_env()
