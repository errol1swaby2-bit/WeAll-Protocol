# Not run

- Full `PYTHONPATH=src python -m pytest -q` was attempted on the uploaded tree and timed out after partial progress in this sandbox.
- Rendered Playwright frontend tests were not run because this supplement only changes source-level status/copy surfaces and the required source checks/typecheck passed.
- `scripts/check_release_hygiene_v1_5.py` was run against the exported archive and failed because the archive lacks repository `.git` metadata for `git check-ignore` and worktree-clean evaluation. Run it in the real git checkout after committing.
