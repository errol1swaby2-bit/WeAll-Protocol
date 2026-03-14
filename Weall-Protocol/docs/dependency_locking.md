# Dependency locking

This repository supports two workflows:

## 1) Dev / CI (editable)

For local development and CI, install in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -e '.[test]'

pytest -q
