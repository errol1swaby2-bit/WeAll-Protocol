# Two independent PCs: bounded live-network rehearsal preparation

Status: **capture machinery and controlled rehearsal instructions only**. Two
physical nodes, authenticated mesh adjacency, independent state convergence,
live PoH across browsers, and public-testnet readiness are **not** established
by checking in these files.

This procedure complements the existing scripts and never substitutes for
protocol authority gates. It is separate from optional Cloudflare static
frontend PR #78.

## Work possible before buying PC B

1. Finish the same-machine and fresh-clone gates on the current laptop.
2. Verify local Python, Node, Docker/Kubo, Git and network connectivity.
3. Rehearse disposable reviewer Genesis and observer preflight on the existing
   PC, labelling any such result **same-machine**.
4. Run the new safe environment inventory and script unit tests.
5. Keep the public seed registry fail-closed until the current ML-DSA
   signature/rotation requirement is actually satisfied.
6. Do not close external-observer, physical-network, PoH, validator,
   storage-durability or public-beta blockers from local scaffolding.

Commands from the Weall-Protocol backend directory:

    python3 -m unittest discover -s tests -p 'test_two_pc_network_evidence.py' -v
    python3 scripts/two_pc_network_evidence.py inventory \
      --machine-id laptop-A \
      --out ~/weall-rehearsal/laptop-A-inventory.json

Existing authoritative operator runbooks:

- docs/REVIEWER_LAN_REHEARSAL_QUICKSTART.md
- docs/FIRST_PROMOTED_VALIDATOR_TWO_MACHINE_TEST.md
- docs/PUBLIC_TESTNET_NAT_FIREWALL_TLS_RECOVERY.md
- docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md
- docs/testnet/EXTERNAL_CROSS_MACHINE_REPLAY_TRANSCRIPT.md
- docs/testnet/M2_LIVE_REVIEWER_RUNBOOK.md
- docs/testnet/REAL_STORAGE_IPFS_OPERATOR_TRANSCRIPT.md

## Planned topology

    Laptop A: disposable Genesis, independent DB/keys/IPFS
       API on a trusted LAN IP or over HTTPS for off-LAN use
       P2P on its separately configured transport port
                         |
                 independently routed LAN
                         |
    PC B: fresh clone, distinct DB/keys/IPFS and peer identity
       observer, signed onboarding, gossip/sync, PoH
       validator promotion only after protocol-granted authority

    Optional Cloudflare Pages frontend:
       static file distribution; connects directly to compatible HTTPS APIs

Prefer a controlled trusted LAN first. Do not put an unsecured HTTP API
or P2P management interface on the open internet. A Windows 11/WSL2 Genesis
host may need the PowerShell forwarding steps printed by its existing
reviewer Genesis script; use the real detected IP addresses and restrict
Windows Firewall to the controlled second machine. API forwarding alone
does not prove mesh connectivity. Do not expose Kubo's administration API,
keys, private onboarding material, or database files.

## Phase 1 — remote reviewer observer onboarding

On A, from the exact review commit:

    cd WeAll-Protocol/Weall-Protocol
    bash scripts/reviewer_setup_env.sh
    bash scripts/reviewer_lan_genesis_rehearsal.sh --lan-ip <LAPTOP_A_LAN_IP>

Leave Genesis running. This is a **disposable reviewer chain**, not
canonical production Genesis. The script prints the correct observer command
and any necessary WSL/Windows port-forwarding notes.

On B, from the exact same commit:

    git clone https://github.com/errol1swaby2-bit/WeAll-Protocol.git
    cd WeAll-Protocol
    git checkout --detach <EXACT_REVIEW_SHA>
    cd Weall-Protocol
    bash scripts/reviewer_setup_env.sh
    bash scripts/reviewer_observer_rehearsal.sh \
      --genesis-api-base http://<LAPTOP_A_LAN_IP>:8000 \
      --pull-reviewer-artifacts \
      --allow-lan-genesis-api \
      --evidence-dir ~/weall-rehearsal/observer-onboarding

A successful observer onboarding rehearsal does **not** by itself prove two
independent mesh nodes: the reviewer observer command submits through
Genesis's API. Keep that evidence distinct.

## Phase 2 — independently running nodes and evidence packets

Both machines must run separate compatible node processes with unique
node keys, unique database paths, and independent runtime state. Keep the
observer's validator/BFT/helper authority disabled until the real
protocol-gated activation procedure succeeds. The public observer bootstrap
must continue to refuse an unsigned or stale seed registry.

Check that each machine has a local /v1/status at
http://127.0.0.1:8000/v1/status and that both can reach the *other*
machine's genuine LAN API.

On A:

    python3 scripts/two_pc_network_evidence.py capture \
      --machine-id laptop-A \
      --local-api http://127.0.0.1:8000 \
      --remote-api http://<PC_B_LAN_IP>:8000 \
      --allow-lan \
      --out ~/weall-rehearsal/laptop-A.json

On B:

    python3 scripts/two_pc_network_evidence.py capture \
      --machine-id pc-B \
      --local-api http://127.0.0.1:8000 \
      --remote-api http://<LAPTOP_A_LAN_IP>:8000 \
      --allow-lan \
      --out ~/weall-rehearsal/pc-B.json

Each capture requests the four read-only endpoints /v1/status, /v1/readyz,
/v1/chain/identity, and /v1/net/self, and stores only a whitelisted subset
of operational facts. It never stores raw secrets, HTTP headers or private
keys. Loopback is disallowed as a remote target. Public HTTP is rejected.
A private LAN HTTP target requires the explicit --allow-lan flag.

Transfer packets via a trusted channel, then compare:

    python3 scripts/two_pc_network_evidence.py compare \
      --a ~/weall-rehearsal/laptop-A.json \
      --b ~/weall-rehearsal/pc-B.json \
      --out ~/weall-rehearsal/two-pc-comparison.json

This verifies commit/tree equality, distinct self-identified machine labels,
node peer identities, bidirectional API visibility and matching chain
commitments. Machine labels are still operator claims, not independent
proof that two devices exist.

### Authenticated P2P evidence (restricted operator diagnostic)

The operator-sensitive /v1/net/peers endpoint is disabled by default in
production. If it is already available through **restricted local operator
access** on both machines, capture again with --operator-peer-debug and run
compare with --require-mesh. Do not enable public peer-debug access just
to obtain a green test. Strict mesh matching requires reciprocal established,
connected, identity-verified peer entries with the expected peer IDs and
public keys. Peer counts alone are not adjacency proof.

### State comparison

Capture both machines at the same height and run compare with
--require-state. A different height is **not comparable** and does not
pass the state comparison. A same-height root mismatch fails. A single
matching snapshot is not proof of durable catch-up or consensus finality;
perform the existing replay, restart, and partition/rejoin gates separately.

Both strict flags can be used together:

    python3 scripts/two_pc_network_evidence.py compare \
      --a ~/weall-rehearsal/laptop-A.json \
      --b ~/weall-rehearsal/pc-B.json \
      --out ~/weall-rehearsal/two-pc-strict.json \
      --require-mesh \
      --require-state

## Phase 3 — behavioral and failure testing

| Area | Existing path | Required real evidence |
| --- | --- | --- |
| Independent clone | reviewer/bootstrap runbooks | two actual checkouts at same SHA |
| Observer onboarding | reviewer_observer_rehearsal.sh | signed remote onboarding and no authority escalation |
| P2P | net/self and restricted local net/peers | authenticated reciprocal peer sessions |
| State catch-up | chain/identity and replay scripts | same-height matching roots and replay proof |
| Transaction propagation | external_observer_live_gate.sh | remote acceptance and confirmation |
| Async/live PoH | M2 async/live reviewer runbooks | independent accounts, cameras and protocol receipts |
| IPFS durability | real-storage/IPFS operator transcript | actual daemon/operator failure and recovery |
| Partition/rejoin | controlled validator scripts | fail-closed safety, recovery and restart |
| Observer promotion | promoted-validator preflight/live gate | protocol-authorized activation only |
| Cloudflare access | draft PR #78 | direct browser-to-node HTTPS, not protocol authority |

## Truth boundary

Do not treat this capture as proof of real physical machine isolation:
different machine labels are operator declarations. External transcript,
independent operator attestation, actual node process logs, replay corpus,
media flows and protocol receipts remain separate evidence obligations.

This tool cannot claim public beta, mainnet, public multi-validator BFT,
production helper execution, live economics, legal approval or a public
storage market. It only prepares and checks narrowly defined network
and state-readiness evidence.
