# Not run / incomplete

- Full `PYTHONPATH=src python -m pytest -q` did not complete within the bounded sandbox attempt. See `transcripts/full_pytest_attempt.txt`.
- Frontend commands were not run because frontend source was not changed by this patch and no frontend package install was performed in the sandbox.
- Real ML-DSA positive-path signing was not run because the sandbox Python environment did not expose a real ML-DSA backend.
- Fresh external observer/local evidence must be rerun after this cryptographic transition because prior signed evidence is Ed25519-era evidence.
