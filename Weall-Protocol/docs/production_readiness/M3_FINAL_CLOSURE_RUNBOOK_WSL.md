# M3 Final Closure Runbook — WSL

This runbook produces the formal Milestone 3 evidence-only direct-child commit.
It does not change the M3 protocol implementation after the implementation
freeze. All closure evidence is generated from live signed transactions and
fresh deterministic replay runs.

## 1. Freeze the implementation

Begin with a clean repository after the M3 closure-tooling patch is committed.
Record that commit as the implementation freeze:

```bash
cd ~/WeAll-Protocol
set -euo pipefail
source .venv-m3/bin/activate

export M3_IMPLEMENTATION_FREEZE_COMMIT="$(git rev-parse HEAD)"
git status --short
test -z "$(git status --porcelain --untracked-files=all)"
```

Do not amend or add source changes after recording this commit. The closure
manifest and evidence-only checker bind every artifact to this exact commit and
tree.

## 2. Prepare the locked environment

```bash
cd ~/WeAll-Protocol
scripts/bootstrap_m3_environment.sh
source .venv-m3/bin/activate
python scripts/check_m3_dependencies.py
```

The frontend dependency tree and Playwright browser must also be present:

```bash
cd ~/WeAll-Protocol/web
npm ci
npx playwright install chromium
npm run typecheck
npm run build
```

## 3. Generate private actor-contract templates

Generate templates outside the repository so browser storage states and local
custody material can never enter the evidence commit:

```bash
export M3_PRIVATE_DIR="$HOME/.local/share/weall/m3-closure-${M3_IMPLEMENTATION_FREEZE_COMMIT:0:12}"
mkdir -p "$M3_PRIVATE_DIR"
chmod 700 "$M3_PRIVATE_DIR"

cd ~/WeAll-Protocol
python scripts/gen_m3_actor_contract_templates.py \
  --out-dir "$M3_PRIVATE_DIR" \
  --implementation-freeze "$M3_IMPLEMENTATION_FREEZE_COMMIT"
```

The directory contains:

- `m3-actors.template.json` — 21 independent browser actors: author, member,
  outsider, nine original reviewers, and nine fresh appeal reviewers;
- `m3-transaction-transcript.template.json` — required positive and negative
  transaction evidence;
- `M3_ACTOR_MANIFEST.template.json` — private runner input seed.

## 4. Start the controlled-testnet backend and frontend

Use the same implementation-freeze checkout for the live stack. The canonical
closure URLs are loopback-only:

```bash
# Terminal A — strict controlled-testnet backend
cd ~/WeAll-Protocol/Weall-Protocol
source ~/WeAll-Protocol/.venv-m3/bin/activate
export PYTHONPATH="$PWD/src"

export WEALL_DEVNET_DIR="$HOME/.local/share/weall/m3-live-${M3_IMPLEMENTATION_FREEZE_COMMIT:0:12}"
export WEALL_DEVNET_AUTO_VENV=0
export WEALL_DEVNET_LIVE_RESET=1
export WEALL_M3_CIVIC_GOVERNANCE_STRICT=1
export WEALL_BALLOT_PROFILE_ID=controlled-testnet-aggregate-v1
export WEALL_BALLOT_PROFILE_ACTIVE=1
export GUNICORN_BIND=127.0.0.1:18401

bash scripts/devnet_boot_genesis_node.sh
# Keep this terminal running.
```

```bash
# Terminal B — frontend
cd ~/WeAll-Protocol/web
VITE_WEALL_DEV_PROXY_TARGET=http://127.0.0.1:18401 \
VITE_WEALL_API_BASE=/ \
npm run dev -- --host 127.0.0.1 --port 5173
```

Before continuing:

```bash
curl -fsS http://127.0.0.1:18401/v1/status >/dev/null
curl -fsS http://127.0.0.1:5173/ >/dev/null

python ~/WeAll-Protocol/scripts/check_m3_live_ballot_profile.py \
  --api-base http://127.0.0.1:18401 \
  --out /tmp/m3-live-ballot-profile.json \
  --implementation-freeze "$M3_IMPLEMENTATION_FREEZE_COMMIT" \
  --implementation-tree "$(git -C ~/WeAll-Protocol rev-parse "$M3_IMPLEMENTATION_FREEZE_COMMIT^{tree}")"
```

## 5. Create and prepare the actors

Create or restore all 21 independent accounts through the real account-custody
flow. Save each Playwright storage-state file under the private directory and
update `m3-actors.template.json` with the exact public account, private
storage-state path, and private signer-state path. Playwright storage state does
not preserve session storage, so the signer-state companion is required to
perform the signed negative attempts without persisting the seed in browser
local storage.

The original reviewer and appeal reviewer pools must each contain at least nine
separate Tier-2 humans. Enroll and opt them into the content-review lane through
real signed transactions. The appeal pool must be disjoint from the original
panel.

Never put recovery files, private keys, mnemonics, cookies, bearer tokens, or
browser storage-state contents under `artifacts/m3-closure/`.

## 6. Execute the signed M3 journey

Using the live UI or the repository's signed transaction client, complete the
main journey:

1. Author creates the public post and group.
2. Member requests and receives group membership.
3. Member creates the group post.
4. Member reports the main post.
5. Nine original reviewers accept, attend, and submit ballots.
6. The main dispute reaches its required final stage.
7. Member opens the appeal.
8. Nine fresh appeal reviewers accept, attend, and submit ballots.
9. The appeal reaches its required final stage.
10. Author creates the proposal; member comments.
11. At least two eligible frozen-round humans vote.
12. The proposal reaches its required final stage.

Also keep separate active negative fixtures:

- a post and group for unauthorized group-write and report tests;
- an active dispute for unselected/conflicted reviewer and immutable-ballot
  tests;
- an active proposal round for ineligible, duplicate, replacement, and revoke
  tests.

Populate the transcript template with the confirmed transaction IDs, canonical
transaction types, actors, subject IDs, and chain ID. Keep the exact expected
negative failure codes from the generated template. Replacement, duplicate,
and revoke attempts must point to their confirmed prior ballot through
`precondition_tx_id`.

## 7. Build and validate the private manifest

Rename or copy the completed actor and transcript files, then build the final
private manifest:

```bash
cd ~/WeAll-Protocol
python scripts/build_m3_actor_manifest.py \
  --implementation-freeze "$M3_IMPLEMENTATION_FREEZE_COMMIT" \
  --backend-base-url http://127.0.0.1:18401 \
  --frontend-base-url http://127.0.0.1:5173 \
  --actors-file "$M3_PRIVATE_DIR/m3-actors.json" \
  --transaction-transcript "$M3_PRIVATE_DIR/m3-transaction-transcript.json" \
  --post-id post:m3:main \
  --group-id group:m3:main \
  --group-post-id post:m3:group-main \
  --dispute-id dispute:m3:main \
  --proposal-id proposal:m3:main \
  --negative-post-id post:m3:negative \
  --negative-group-id group:m3:negative \
  --negative-dispute-id dispute:m3:negative \
  --negative-proposal-id proposal:m3:negative \
  --expected-dispute-stage finalized \
  --expected-proposal-stage finalized \
  --minimum-final-ballots 2 \
  --out "$M3_PRIVATE_DIR/M3_ACTOR_MANIFEST.json"

python scripts/validate_m3_actor_manifest.py \
  --manifest "$M3_PRIVATE_DIR/M3_ACTOR_MANIFEST.json" \
  --implementation-freeze "$M3_IMPLEMENTATION_FREEZE_COMMIT" \
  --out-public-manifest /tmp/M3_ACTOR_MANIFEST.public.json \
  --out-transcript /tmp/M3_TRANSACTION_TRANSCRIPT.public.json
```

Validation must pass before the full closure run.

## 8. Generate the complete evidence tree

The source tree must still be clean and `HEAD` must still equal the
implementation freeze:

```bash
cd ~/WeAll-Protocol
export WEALL_M3_ACTOR_MANIFEST="$M3_PRIVATE_DIR/M3_ACTOR_MANIFEST.json"

test "$(git rev-parse HEAD)" = "$M3_IMPLEMENTATION_FREEZE_COMMIT"
test -z "$(git status --porcelain --untracked-files=all)"

scripts/run_m3_complete_closure.sh
```

The runner requires every gate to pass, including:

- locked dependency preflight;
- traceability and all generated-artifact freshness checks;
- clean-checkout reproduction;
- focused and complete backend suites;
- helper serial equivalence and deterministic fallback;
- frontend source, contract, typecheck, build, and production-safety gates;
- signed multi-actor Playwright verification;
- restart/replay equality;
- independent two-node equality;
- observer catch-up without authority;
- evidence privacy scan.

## 9. Create the evidence-only direct child

Do not commit any source change. Stage only the generated evidence tree:

```bash
cd ~/WeAll-Protocol
git add artifacts/m3-closure

M3_IMPLEMENTATION_FREEZE_COMMIT="$M3_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m3_evidence_only_commit.sh --cached

git diff --cached --name-only
git commit -m "Close M3 with integrated controlled-testnet evidence"
```

The new commit must be the direct child of the implementation freeze. Verify it:

```bash
M3_IMPLEMENTATION_FREEZE_COMMIT="$M3_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m3_evidence_only_commit.sh

git log -2 --oneline
git status --short
```

The final working tree must be clean. The manifest under
`artifacts/m3-closure/M3_EVIDENCE_MANIFEST.json` is the formal M3 closure
record.

## Failure handling

If any gate fails, do not commit partial evidence. Inspect the corresponding
log under `artifacts/m3-closure/`, correct the external setup or evidence input,
remove the incomplete evidence directory, and rerun from the unchanged
implementation freeze. Any source fix creates a new implementation freeze and
requires all evidence to be regenerated.
