import os


def validate_environment():
    required = [
        "WEALL_MODE",
    ]

    for r in required:
        if r not in os.environ:
            raise RuntimeError(f"Missing required env: {r}")

    if os.environ.get("WEALL_MODE") == "prod":
        if os.environ.get("WEALL_ALLOW_UNSIGNED_TXS") == "1":
            raise RuntimeError("Unsafe config: unsigned txs enabled in prod")
