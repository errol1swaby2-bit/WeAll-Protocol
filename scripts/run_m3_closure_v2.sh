#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${WEALL_M3_CLOSURE_V2_PYTHON:-$REPO/.venv-m3/bin/python}"

test -x "$PYTHON"

exec env   PYTHONPATH="$REPO/tooling${PYTHONPATH:+:$PYTHONPATH}"   "$PYTHON" -m m3_closure_v2 "$@"
