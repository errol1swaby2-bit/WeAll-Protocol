"""R1C: authority and reachability diagnostics; no protocol changes."""
from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from test_r1b_helper_hierarchy import explicit_tx, materialized
from weall.runtime.helper_block_validation import validate_received_helper_execution
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
    make_tx_order_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperCertificateStore, HelperDispatchContext
from weall.runtime.helper_merge import HelperDeltaOp, merge_materialized_lane_results
from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint, plan_parallel_execution
from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_admission_types import TxEnvelope


def keypair(seed_byte):
    seed = (bytes([seed_byte]) * 32).hex()
    pub = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(seed)).public_key().public_bytes_raw().hex()
    return seed, pub


def test_envelope_roundtrip_removes_explicit_scope():
    raw = explicit_tx("t1", "content:post:unrelated")
    raw["payload"] = {"post_id": "fixture", "content_id": "fixture"}
    wire = TxEnvelope.from_any(raw).to_json()
    assert "write_set" not in wire
    assert "read_set" not in wire
    assert "state_prefixes" not in wire
    derived = build_tx_access_set({**wire, "tx_id": "t1"})
    assert "content:post:fixture" in derived.writes
    assert "content:post:unrelated" not in derived.writes


def test_derived_identifier_slash_is_not_escaped():
    # Observation at descriptor boundary ONLY. The handler may reject this ID,
    # and a logical object identifier need not denote a physical nested path.
    raw = explicit_tx("t1", "unused")
    raw["payload"] = {"post_id": "fixture/body", "content_id": "fixture/body"}
    wire = TxEnvelope.from_any(raw).to_json()
    derived = build_tx_access_set({**wire, "tx_id": "t1"})
    assert "content:post:fixture/body" in derived.writes


def block_fixture():
    validators = ["v1", "v2", "v3", "v4"]
    txs = [explicit_tx("t1", "content:post:1"), explicit_tx("t2", "content:post:1/body")]
    plans = plan_parallel_execution(
        txs=txs, validators=validators, validator_set_hash="vhash", view=7, leader_id="v1",
        state_snapshot_metadata={
            "validator_epoch": 9,
            "quarantined_helper_ids": [],
            "helper_capacity_by_helper": {},
            "helper_capabilities_by_helper": {},
            "helper_planning_inputs_source": "state_root",
            "allow_helper_overcommit": True,
        },
    )
    lane = next(p for p in plans if p.helper_id)
    plan_id = canonical_lane_plan_fingerprint(plans)
    reads = sorted({v for a in lane.access_sets for v in a.reads})
    writes = sorted({v for a in lane.access_sets for v in a.writes})
    seed, pub = keypair(37)
    cert = HelperExecutionCertificate(
        chain_id="c1", block_height=22, view=7, leader_id="v1",
        helper_id=lane.helper_id, validator_epoch=9, validator_set_hash="vhash",
        lane_id=lane.lane_id, tx_ids=lane.tx_ids, tx_order_hash=make_tx_order_hash(lane.tx_ids),
        receipts_root=hash_receipts([{"tx_id": t, "ok": True} for t in lane.tx_ids]),
        write_set_hash=hash_ordered_strings(writes), read_set_hash=hash_ordered_strings(reads),
        lane_delta_hash=hash_ordered_strings([]), namespace_hash=make_namespace_hash(lane.namespace_prefixes),
        plan_id=plan_id,
    )
    rows = [{"lane_id": p.lane_id, "helper_id": str(p.helper_id or ""), "tx_ids": list(p.tx_ids),
             "descriptor_hash": p.descriptor_hash, "plan_id": plan_id} for p in plans]
    block = {"height":22, "view":7, "proposer":"v1", "block_ts_ms":1000, "txs":txs,
             "helper_execution":{"plan_id":plan_id, "view":7, "validator_epoch":9,
             "validator_set_hash":"vhash", "coordinator_id":"v1", "lanes":rows,
             "accepted_certificates":[], "helper_reputation":{"transition_policy":"diagnostic_only_v1","state_committed":False}}}
    return block, lane, cert, seed, pub, validators


@pytest.mark.parametrize("mutation,expected", [("none", True), ("signature", False),
    ("epoch", False), ("namespace", False), ("write_commitment", True), ("delta_commitment", True)])
def test_receiver_signed_metadata_boundary(mutation, expected):
    block, lane, cert, seed, pub, validators = block_fixture()
    if mutation == "epoch":
        cert = replace(cert, validator_epoch=10)
    if mutation == "namespace":
        cert = replace(cert, namespace_hash="bad-namespace")
    if mutation == "write_commitment":
        # Signed but not semantically checked by metadata verifier. Observation,
        # not evidence that arbitrary writes become authoritative.
        cert = replace(cert, write_set_hash="0" * 64)
    if mutation == "delta_commitment":
        cert = replace(cert, lane_delta_hash="0" * 64)
    cert = sign_helper_certificate(cert, privkey=seed)
    if mutation == "signature":
        sig = cert.helper_signature
        cert = replace(cert, helper_signature=f"{int(sig[:2],16)^1:02x}" + sig[2:])
    block["helper_execution"]["accepted_certificates"] = [{
        "lane_id":lane.lane_id,"helper_id":lane.helper_id,"accepted":True,
        "code":"accepted","plan_id":cert.plan_id,"certificate":cert.to_json()}]
    ok, reason = validate_received_helper_execution(
        block=block, state={}, chain_id="c1", validators=validators,
        validator_pubkeys={lane.helper_id:pub}, validator_epoch=9, validator_set_hash="vhash")
    print("receiver", mutation, ok, reason)
    assert ok is expected, reason


@pytest.mark.parametrize("reverse", [False, True])
def test_signed_dispatch_then_materialized_hierarchical_merge(reverse):
    # The exact R1B synthetic two-lane plans now go through real signature
    # verification and the dispatch store. No live transport, manifest or QC.
    base = {"accounts":{"x":{"balance":10,"reputation":3}}}
    a = materialized("PARALLEL_CONTENT", "t1", (), ("accounts/x",),
                     (HelperDeltaOp(op="set", path="accounts/x", value={"balance":20}),))
    b = materialized("PARALLEL_CONTENT#1", "t2", (), ("accounts/x/balance",),
                     (HelperDeltaOp(op="set", path="accounts/x/balance", value=99),))
    plans = (a.lane_plan, b.lane_plan)
    plan_id = canonical_lane_plan_fingerprint(plans)
    signed = []
    pubkeys = {}
    for i, m in enumerate((a,b), 41):
        seed, pub = keypair(i)
        cert = sign_helper_certificate(replace(m.cert, plan_id=plan_id), privkey=seed)
        pubkeys[cert.helper_id] = pub
        signed.append(replace(m, cert=cert))
    ctx = HelperDispatchContext(chain_id="audit-fixture", block_height=5, view=11,
        leader_id="@leader", validator_epoch=7, validator_set_hash="fixture-vhash",
        strict_helper_certificate_consistency=True, plan_id=plan_id)
    store = HelperCertificateStore(context=ctx, lane_plans=plans, helper_pubkeys=pubkeys)
    for p in plans:
        store.start_request(lane_id=p.lane_id, started_ms=1000)
    results = list(reversed(signed)) if reverse else signed
    for result in results:
        status = store.ingest_certificate(cert=result.cert, peer_id=result.cert.helper_id, now_ms=1001)
        assert status.accepted, f"dispatch fixture failed: {status.code}"
    accepted = store.accepted_certificates()
    assert len(accepted) == 2
    outcome = merge_materialized_lane_results(base_state=base, lane_results=results,
        lane_plans=plans, accepted_certificates=accepted)
    print("signed merge", reverse, outcome)
    assert outcome.merged_state == base
    assert not outcome.accepted_lane_ids
    assert len(outcome.serialized_lane_ids) == 2
