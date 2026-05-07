# New Node Operator Quickstart

This guide explains the safe first-run path for a new person who wants to run WeAll software, create an account, complete human verification, enroll as a node operator, and later boot an approved production service node.

The important rule is simple:

- **Onboarding/observer mode is for joining the network safely.** It can read/sync state, serve the local app, create accounts, submit Proof-of-Humanity verification transactions, register a separate node key, and submit node-operator enrollment.
- **Production service mode is for already-approved node operators.** It is intentionally fail-closed and requires Live Verified Human status, an active NodeOperator role, and a registered node key.

A new user should start with onboarding mode. Do not try to start production service mode until protocol eligibility checks activate baseline Node Operator status.

---

## 1. Clone the repository

```bash
cd ~
git clone https://github.com/errol1swaby2-bit/WeAll-Protocol.git
cd WeAll-Protocol/Weall-Protocol
```

Install the normal project dependencies described in the main README for your environment.

---

## 2. Start the safe onboarding node

Use the onboarding boot wrapper first:

```bash
./scripts/boot_onboarding_node.sh
```

This starts WeAll in a safe observer/onboarding posture. It is designed for first-time users and node-operator candidates.

Allowed in this mode:

- read and sync finalized chain state
- serve the local onboarding UI
- create an account
- save a recovery key
- submit account registration transactions
- submit async and live Proof-of-Humanity verification transactions
- generate and register a separate node key
- submit node-operator enrollment

Blocked in this mode:

- validator signing
- block proposal
- validator voting
- helper authority
- storage-provider service authority
- production service rewards
- role activation
- Proof-of-Humanity grants

Onboarding mode does not make you a node operator. It only gives you a safe way to complete the steps required to become eligible.

---

## 3. Open the local app

Open the local frontend shown by the boot output. In a local development install this is usually:

```text
http://localhost:5173
```

Use the app to continue the onboarding flow.

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

Baseline Node Operator status does not automatically grant validator or storage-provider responsibilities. Validator readiness and reputation checks must pass before consensus authority. Those are optional responsibilities under the Node Operator umbrella.

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
