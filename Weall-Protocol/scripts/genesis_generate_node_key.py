# projects/Weall-Protocol/scripts/genesis_generate_node_key.py
#!/usr/bin/env python3
"""Genesis Node Key Generator (Ed25519)

Genesis-only helper.

Creates:
  secrets/weall_node_privkey  (32-byte seed, hex)
  secrets/weall_node_pubkey   (32-byte public key, hex)

Safety:
  - Refuses to overwrite existing key files.

Format rationale:
  - Backend supports hex keys.
  - Ed25519PrivateKey.from_private_bytes expects a 32-byte seed.
  - Public key is 32 bytes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


SECRETS_DIR = Path("secrets")
PRIV_PATH = SECRETS_DIR / "weall_node_privkey"
PUB_PATH = SECRETS_DIR / "weall_node_pubkey"


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def main() -> int:
    if PRIV_PATH.exists() or PUB_PATH.exists():
        print("ERROR: Genesis keys already exist. Refusing to overwrite.")
        print(f"  {PRIV_PATH} exists={PRIV_PATH.exists()}")
        print(f"  {PUB_PATH} exists={PUB_PATH.exists()}")
        return 1

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)

    priv = Ed25519PrivateKey.generate()

    # 32-byte seed
    priv_seed = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )

    # 32-byte pubkey
    pub_bytes = priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    PRIV_PATH.write_text(priv_seed.hex() + "\n", encoding="utf-8")
    PUB_PATH.write_text(pub_bytes.hex() + "\n", encoding="utf-8")

    _chmod_best_effort(PRIV_PATH, 0o600)
    _chmod_best_effort(PUB_PATH, 0o644)

    print("Genesis node identity created.")
    print(f"Private key seed (hex): {PRIV_PATH}")
    print(f"Public key (hex):       {PUB_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
