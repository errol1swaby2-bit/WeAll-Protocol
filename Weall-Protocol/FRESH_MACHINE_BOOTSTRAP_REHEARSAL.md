# Fresh-Machine Bootstrap Rehearsal

## 1. Clone and enter repo
```bash
git clone <your-repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
```

## 2. Build/update deterministic artifacts
```bash
chmod +x scripts/*.sh
./scripts/lock_deps.sh
python3 scripts/gen_tx_index.py
```

## 3. Build validator bootstrap bundle
```bash
python3 scripts/build_validator_bootstrap_bundle.py
python3 scripts/verify_validator_bootstrap.py
python3 scripts/public_validator_preflight.py
```

## 4. Run final gate
```bash
pytest -q   tests/test_priority1_signed_manifest.py   tests/test_priority6_validator_compatibility_manifest.py   tests/test_production_bootstrap_network.py   tests/test_priority4_public_validator_preflight.py   tests/test_priority4_release_manifest_guardrails.py   tests/test_priority3_profile_startup_alignment.py   tests/test_handshake_profile_safety.py   tests/test_multinode_liveness.py   tests/test_net_partition_fail_closed.py   tests/test_priority12_network_recovery.py   tests/test_priority1_restart_combined_safety_liveness.py   tests/test_priority2_consensus_resilience_matrix.py   tests/test_priority1_multinode_divergence_resolution.py   tests/test_priority1_heavy_soak.py   tests/test_priority3_crash_restart_matrix.py
```

## 5. Production bootstrap rehearsal
```bash
./scripts/bootstrap_prod_node.sh
python3 scripts/prod_smoke.py
```
