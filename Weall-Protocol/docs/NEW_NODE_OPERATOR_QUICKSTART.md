# New Node Operator Quickstart

This guide explains the safe first-run path for a new person who wants to run WeAll software, create an account, complete human verification, enroll as a node operator, and later boot an approved production service node.

The important rule is simple:

- **Onboarding/observer mode is for joining the network safely.** It can read/sync state, serve the local app, create accounts, submit Proof-of-Humanity verification transactions, register a separate node key, and submit node-operator enrollment.
- **Production service mode is for already-approved node operators.** It is intentionally fail-closed and requires Live Verified Human status, an active NodeOperator role, and a registered node key.

A new user should start with onboarding mode. Do not try to start production service mode until protocol eligibility checks activate baseline Node Operator status.

---

## 1. Clone the repository and install dependencies

Choose the network path **before** attempting to start an observer. The
production-oriented `boot_onboarding_node.sh` is not a Genesis producer and
must not be used to manufacture a network or bypass observer preflight.

For Ubuntu / WSL, from a clean clone:

```bash
cd ~
git clone https://github.com/errol1swaby2-bit/WeAll-Protocol.git
cd WeAll-Protocol/Weall-Protocol
python3 --version
node --version
npm --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install -e . --no-deps
python -c 'import weall; print("WeAll backend installed")'
```

Use the **exact commit or branch under review** when conducting an
acceptance test; the moving default branch is not interchangeable with an
unmerged PR or integration preview. Keep any existing node keys or chain
databases separate from this clean-clone test. On Windows, use a fresh browser
profile to avoid carrying over app-local sessions.

## 2. Choose the network path and start the node

### Path A — Disposable local two-node rehearsal (Ubuntu / WSL)

Use this path if you **do not yet have a reachable Genesis operator and a
matching public observer bundle**, or if your goal is to test the local
frontend, PoH and two-node transaction flow.

Requirements: Node.js/npm, Python dependencies above, a running Docker daemon
with Docker Compose (or a compatible separately configured Kubo IPFS daemon).
The local launcher starts IPFS, the Genesis backend, the observer-edge backend,
two frontends, and the operator reconcile/state-sync workers:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
docker info --format '{{.ServerVersion}}'
bash scripts/devnet_local_two_frontend_rehearsal.sh
```

Expected final output includes `Local two-frontend rehearsal ready`,
`observer_ui=http://127.0.0.1:5173/#/verification` and
`genesis_ui=http://127.0.0.1:5174/#/reviews` (ports can be overridden).
Leave the launcher running in its terminal. The observer API normally uses
port 8002 and Genesis API uses 8001.

**Truth boundary:** This is a **disposable, single-machine controlled devnet**,
not production onboarding, an externally operated two-machine proof, or a
public-testnet launch. The launcher automatically creates `@errol` and a
special local Genesis reviewer `@devnet-genesis` (Tier 2). Their provisioned
keys and development bootstrap manifests are NOT evidence that a stranger
completed self-service account creation or PoH. To evaluate an ordinary new
participant, explicitly test creation and recovery of an additional account
using a clean browser profile; record which steps are actually possible.

The launcher may encounter a Docker Desktop/WSL IPFS port-forward error at
5001/8080, retry and use 15001/18080. The run is successful only if the
final readiness checks pass. An intermediate observer account-registration
`upstream_not_confirmed` / `local_state_synced=false` warning is **not** an
upstream confirmation proof; the current rehearsal can recover using account
state on both nodes. Report it separately rather than marking transaction
status convergence as proven.

### Path B — Join an existing operator-run network

This path needs **two externally supplied, matching public artifacts** from
the chosen network's trusted operator: an observer/onboarding bundle JSON and
its chain manifest. It also needs a reachable Genesis API advertised or
confirmed by the operator. No publicly available Genesis/bundle is asserted by
this guide; until these exist, new users cannot complete this path.

Use the tester wrapper rather than executing a bare production boot command:
it verifies/installs the bundle, prepares observer-only runtime settings,
starts the local frontend, and runs the preflight before boot.

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

bash scripts/weall_tester_node.sh \
  --bundle "/path/from/operator/public-observer-bundle.json" \
  --manifest "/path/from/operator/matching-chain-manifest.json" \
  --genesis-api-base "https://operator-supplied-genesis.example"
```

**Replace all three placeholders with real operator-provided values** before
running. Do not generate a fake production bundle, change its trust anchors,
disable signature/manifest checks, or set `WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED=1`
to make an unverified join appear successful. Production observer preflight
must remain fail-closed.

Advanced/operator-only: if the bundle was already validated and the exact
observer environment provisioned separately, `./scripts/boot_onboarding_node.sh`
is the low-level wrapper. Calling it **without** a bundle/preflight is an
expected rejection, not a working first-run procedure. The wrapper is not
itself a frontend launcher.

For an actual **two-machine** disposable Genesis-plus-observer reviewer proof,
use `docs/REVIEWER_LAN_REHEARSAL_QUICKSTART.md` instead. It is different
from Path A's two local processes.

## 3. Open the app appropriate to your path

- **Local Path A:** observer app at `http://127.0.0.1:5173/#/verification`;
  Genesis reviewer app at `http://127.0.0.1:5174/#/reviews`.
  The two UIs deliberately use different bootstrap identities.
- **Network Path B:** use the `frontend` URL printed by
  `weall_tester_node.sh` (normally `http://127.0.0.1:5173`).

Continue with the account/recovery steps below, but do not treat
pre-provisioned local rehearsal accounts as fresh-user account creation.
When a network operator or a human reviewer is required, record that
dependency rather than manufacturing authority in the browser.

---

## 4. Create your account and save your recovery key

On the login page:

1. Choose **Create account**.
2. Create your account key.
3. Download and save your recovery file.
4. Confirm that you saved your recovery key.

Your recovery key is your long-term account backup. Keep it private. Anyone with the recovery key can restore the account key.

Do not use your account recovery key as a node key.

---

## 5. Complete account verification

Open **Account Verification** in the app.

Complete the two verification steps:

1. **Verified Person / Tier 1** — async human verification.
2. **Trusted Verified Person / Tier 2** — live human verification.

Tier 1 lets you participate in basic verified-human actions. Tier 2 is required before you can become eligible for high-trust responsibilities such as node operator service.

Verification is finalized by protocol state. The frontend can guide the flow, but it is not the authority.

---

## 6. Generate a separate node key

After verification, open the Account page and go to the node-operator setup section.

Choose:

```text
Generate and download node key
```

This creates a separate operational node key. The node key is not your account recovery key.

Store the node key file securely on the machine that will run the node.

Recommended path example:

```bash
mkdir -p ~/.weall/keys
mv ~/Downloads/weall-node-key-*.json ~/.weall/keys/weall-node.key
chmod 600 ~/.weall/keys/weall-node.key
```

---

## 7. Register the node public key

Use the Account page to register the node public key to your account.

This registration is account-signed, but the operational node key remains separate. The chain must know which node public key is authorized for your account before production service boot can pass.

---

## 8. Submit node-operator enrollment

Use the Account page to submit node-operator enrollment.

The user-actionable step is enrollment, not activation.

You cannot self-activate as a production node operator. After enrollment, the protocol checks eligibility and automatically activates baseline Node Operator status when prerequisites are met.

Expected status after enrollment:

```text
Node operator enrollment submitted
Checking eligibility
```

---

## 9. Wait for protocol eligibility activation

A baseline Node Operator becomes production-service eligible after deterministic protocol eligibility checks activate the enrollment on-chain.

The required state is:

- account exists
- account is Trusted Verified Person / Tier 2
- node public key is registered to the account
- NodeOperator role is active
- account is not banned, locked, or suspended
- production preflight passes

Until then, keep running onboarding/observer mode.


### Optional responsibilities under Node Operator

Baseline Node Operator status does not automatically grant validator or storage-provider responsibilities. Validator readiness and reputation checks must pass before consensus authority. The validator opt-in transaction must carry the full readiness receipt fields (including the receipt hash, checks, BFT key, manifest/tx-index/runtime-profile hashes, chain/schema/protocol versions, and expiry height); the deterministic scheduler validates that committed evidence before emitting validator readiness and role transitions. Those are optional responsibilities under the Node Operator umbrella.

- Validator responsibility requires explicit opt-in, Tier 2 status, sufficient reputation, and validator readiness. Baseline Node Operator status does not grant validator authority.
- Storage responsibility requires explicit opt-in, Tier 2 status, sufficient reputation, and storage capacity probe before allocation.
  Declared capacity is not proven capacity. Proof pending is not allocation eligible.
  The protocol should only treat storage responsibility as allocation-ready after `proven_capacity_bytes` is greater than zero.

---

## 10. Boot as an approved production node operator

After baseline Node Operator status activates, restart with the explicit production node-operator boot wrapper:

```bash
WEALL_BOUND_ACCOUNT='@yourhandle' \
WEALL_NODE_PRIVKEY_FILE="$HOME/.weall/keys/weall-node.key" \
WEALL_NODE_PUBKEY='<registered-node-public-key>' \
./scripts/boot_node_operator.sh
```

This mode is intentionally fail-closed. If the chain does not show Tier 2 status, active NodeOperator authority, and the registered node key, the node must not enter production service authority.

---

## Optional: run the candidate demo smoke harness

After the onboarding and service boot scripts are in place, you can run the repository smoke harness:

```bash
./scripts/fresh_node_operator_candidate_demo.sh
```

By default this is a safe structural check. It verifies that the documented path still matches the codebase and that the onboarding path does not use production-authority shortcuts.

If you already have a local onboarding API running and want to drive the candidate path, use:

```bash
WEALL_FRESH_OPERATOR_DEMO_EXECUTE=1 WEALL_API='http://127.0.0.1:8001' ./scripts/fresh_node_operator_candidate_demo.sh
```

The executable mode stops at **node-operator candidate / eligibility activation**. It does not grant production node-operator authority.

---

## 11. Troubleshooting

### `./scripts/boot_onboarding_node.sh: Permission denied`

A released clone should store the launcher as executable (`100755`).
Check with `git ls-files --stage Weall-Protocol/scripts/boot_onboarding_node.sh`
from the repository root. On a historyless/archive checkout that lost modes,
`bash scripts/boot_onboarding_node.sh` avoids relying on the executable bit;
it **does not** remove the bundle/preflight requirement.

### `WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE` not set

You selected the production-oriented low-level wrapper without a validated
bundle. Follow Path B with operator-provided anchors, or Path A for a disposable
local network. Do not bypass the preflight.

### IPFS WSL Docker ports are unavailable

For Path A, watch for automatic fallback from API/gateway ports 5001/8080
to 15001/18080. A transient bind failure is not proof of total boot failure;
the final `Local two-frontend rehearsal ready` line establishes launcher
readiness. If fallback also fails, report the Docker/WSL forwarding error.

### Observer registration reports `upstream_not_confirmed`

The controlled launcher can fall back to account-state proof on both nodes;
this **does not** establish upstream transaction-status reconciliation.
Record the reported `tx_id`, chain height and both node status responses
(without secrets) as a separate synchronization/evidence issue.


### “Account is not Live Verified”

Complete Trusted Verified Person / Tier 2 live verification first.

### “NodeOperator role is not active”

Your enrollment was submitted, but protocol eligibility checks have not activated baseline Node Operator status yet. Complete Tier 2, node-key registration, and account-standing prerequisites, then wait for a new block.

### “Node key is not authorized”

Generate a separate node key and register its public key to your account. Make sure the public key in the boot command matches the registered node key.

### “Do I use my recovery key as the node key?”

No. Your recovery key is your account backup. The node key is a separate operational key. Production node config should use `WEALL_NODE_PRIVKEY_FILE`, not an account recovery secret.

---

## Safe mental model

```text
Onboarding node = safe way to join and verify.
Node key = operational key for a node machine.
Node-operator enrollment = your application/intent.
Node-operator activation = protocol-checked baseline service authority.
Production service boot = only after protocol eligibility activation.
```


## Production storage capacity probe

Storage responsibility is production-gated by challenge/response verification. Declared capacity is only an intent signal. A system verifier issues a `STORAGE_CHALLENGE_ISSUE` capacity challenge, the operator answers with `STORAGE_CHALLENGE_RESPOND`, and only a system verification response may set `proven_capacity_bytes` and make storage allocation eligible. User responses alone never prove capacity. Expired challenges cannot be used.


## Validator live readiness check

Validator responsibility requires a live readiness receipt generated from node-local checks. Use `scripts/validator_readiness_check.py generate` to bind account id, node pubkey, BFT pubkey, chain id, schema version, protocol version, manifest hash, tx index hash, runtime profile hash, required readiness checks, and expiry height into a deterministic `readiness_receipt_hash`. `VALIDATOR_READINESS_VERIFY` must carry that receipt; opt-in alone does not grant consensus authority.


## Fresh node-to-service E2E harness

For a production-shaped local check of the whole operator path, run:

```bash
./scripts/fresh_node_to_service_e2e.sh
```

By default this is a safe dry-run / structural harness. It exercises the local storage probe runner and validator readiness receipt tools, checks the onboarding/service boot split, and writes a production-service example environment without granting authority.

To drive the user-transaction portion against a running local onboarding API, run:

```bash
WEALL_FRESH_SERVICE_E2E_EXECUTE=1 ./scripts/fresh_node_to_service_e2e.sh
```

This path still does not bypass system verification. Baseline Node Operator, storage responsibility, and validator responsibility must become active through protocol eligibility, capacity-probe verification, and validator-readiness verification before production service boot is authoritative.
