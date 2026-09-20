from weall.crypto.signature_profiles import PQ_MLDSA_V1

REMOVED_CLASSICAL_PROFILE = "classical-signature-profile-removed"
from weall.runtime.block_signature_profiles import validate_validator_operator_record


def test_validator_operator_record_requires_profile_in_closed_testnet(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_validator_operator_record({"node_pubkey": "aa"}, require_verifier=False)
    assert ok is False
    assert reason == "validator_signature_profile_missing"


def test_validator_operator_record_rejects_legacy_without_allowlist(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_validator_operator_record(
        {"sig_profile": REMOVED_CLASSICAL_PROFILE, "node_pubkey": "aa"}, require_verifier=False
    )
    assert ok is False
    assert reason in {"signature_profile_not_allowed", "unknown_signature_profile"}


def test_validator_operator_record_accepts_pq_shape_without_verifier(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    ok, reason = validate_validator_operator_record(
        {"sig_profile": PQ_MLDSA_V1, "node_pubkey": "aa"}, require_verifier=False
    )
    assert (ok, reason) == (True, "ok")


from weall.crypto.pq_mldsa import generate_mldsa65_keypair
from weall.crypto.sig import sign_signature_for_profile
from weall.runtime.bft_hotstuff import (
    BftVote,
    QuorumCert,
    canonical_proposal_message,
    canonical_vote_message,
    verify_proposal_json,
    verify_qc,
)


def test_bft_vote_qc_and_proposal_verify_with_real_mldsa(monkeypatch):
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    validators = ["@v1", "@v2", "@v3", "@v4"]
    keypairs = {v: generate_mldsa65_keypair() for v in validators}
    vpub = {v: keypairs[v]["pubkey"] for v in validators}
    votes = []
    for signer in validators[:3]:
        msg = canonical_vote_message(
            chain_id="weall-testnet-v1",
            view=1,
            block_id="b1",
            block_hash="h1",
            parent_id="b0",
            signer=signer,
            validator_epoch=7,
            validator_set_hash="vs1",
            sig_profile=PQ_MLDSA_V1,
        )
        sig = sign_signature_for_profile(
            sig_profile=PQ_MLDSA_V1, message=msg, privkey=keypairs[signer]["privkey"]
        )
        vote = BftVote(
            chain_id="weall-testnet-v1",
            view=1,
            block_id="b1",
            block_hash="h1",
            parent_id="b0",
            signer=signer,
            pubkey=vpub[signer],
            sig=sig,
            sig_profile=PQ_MLDSA_V1,
            validator_epoch=7,
            validator_set_hash="vs1",
        )
        assert vote.verify()
        votes.append(vote.to_json())
    qc = QuorumCert(
        chain_id="weall-testnet-v1",
        view=1,
        block_id="b1",
        block_hash="h1",
        parent_id="b0",
        votes=tuple(votes),
        validator_epoch=7,
        validator_set_hash="vs1",
    )
    assert verify_qc(qc=qc, validators=validators, vpub=vpub)

    msg = canonical_proposal_message(
        chain_id="weall-testnet-v1",
        view=2,
        block_id="b2",
        block_hash="h2",
        parent_id="b1",
        proposer="@v1",
        validator_epoch=7,
        validator_set_hash="vs1",
        justify_qc_id="b1",
        sig_profile=PQ_MLDSA_V1,
    )
    sig = sign_signature_for_profile(
        sig_profile=PQ_MLDSA_V1, message=msg, privkey=keypairs["@v1"]["privkey"]
    )
    assert verify_proposal_json(
        proposal={
            "chain_id": "weall-testnet-v1",
            "view": 2,
            "block_id": "b2",
            "block_hash": "h2",
            "prev_block_id": "b1",
            "proposer": "@v1",
            "proposer_pubkey": vpub["@v1"],
            "proposer_sig": sig,
            "proposer_sig_profile": PQ_MLDSA_V1,
            "validator_epoch": 7,
            "validator_set_hash": "vs1",
            "justify_qc": {"block_id": "b1"},
        },
        validators=validators,
        vpub=vpub,
        expected_leader="@v1",
    )


def test_bft_forged_proposal_cannot_substitute_embedded_key_for_registry(monkeypatch):
    import weall.runtime.bft_hotstuff as bft_mod
    from weall.runtime.bft_hotstuff import verify_proposal_json

    validators = ["@v1", "@v2", "@v3", "@v4"]
    seen = []

    def _fake_verify(*, sig_profile, message, sig, pubkey):
        del sig_profile, message, sig
        seen.append(pubkey)
        return pubkey == "attacker-v1"

    monkeypatch.setattr(bft_mod, "_verify_bft_signature", _fake_verify)
    proposal = {
        "chain_id": "batch-a",
        "view": 7,
        "block_id": "b7",
        "block_hash": "h7",
        "prev_block_id": "b6",
        "proposer": "@v1",
        "proposer_pubkey": "attacker-v1",
        "proposer_sig": "forged-sig",
    }
    assert (
        verify_proposal_json(
            proposal=proposal,
            validators=validators,
            vpub={"@v1": "registry-v1"},
            expected_leader="@v1",
        )
        is False
    )
    assert seen == []


def test_bft_qc_cannot_substitute_embedded_vote_keys_for_registry(monkeypatch):
    import weall.runtime.bft_hotstuff as bft_mod
    from weall.runtime.bft_hotstuff import QuorumCert, verify_qc

    validators = ["@v1", "@v2", "@v3", "@v4"]
    vpub = {v: f"registry-{v}" for v in validators}
    seen = []

    def _fake_verify(*, sig_profile, message, sig, pubkey):
        del sig_profile, message, sig
        seen.append(pubkey)
        return pubkey.startswith("attacker-")

    monkeypatch.setattr(bft_mod, "_verify_bft_signature", _fake_verify)
    qc = QuorumCert(
        chain_id="batch-a",
        view=8,
        block_id="b8",
        block_hash="h8",
        parent_id="b7",
        votes=tuple(
            {
                "signer": signer,
                "pubkey": f"attacker-{signer}",
                "sig": f"forged-{signer}",
            }
            for signer in validators[:3]
        ),
    )
    assert verify_qc(qc=qc, validators=validators, validator_pubkeys=vpub) is False
    assert seen == []


def test_bft_vote_timeout_aggregation_rejects_mismatched_embedded_keys(monkeypatch):
    import weall.runtime.bft_hotstuff as bft_mod
    from weall.runtime.bft_hotstuff import BftTimeout, BftVote, HotStuffBFT

    validators = ["@v1", "@v2", "@v3", "@v4"]
    vpub = {v: f"registry-{v}" for v in validators}
    seen = []

    def _fake_verify(*, sig_profile, message, sig, pubkey):
        del sig_profile, message, sig
        seen.append(pubkey)
        return True

    monkeypatch.setattr(bft_mod, "_verify_bft_signature", _fake_verify)
    bft = HotStuffBFT(chain_id="batch-a")
    vote = BftVote(
        chain_id="batch-a",
        view=1,
        block_id="b1",
        block_hash="h1",
        parent_id="genesis",
        signer="@v1",
        pubkey="attacker-v1",
        sig="forged-vote",
    )
    timeout = BftTimeout(
        chain_id="batch-a",
        view=1,
        high_qc_id="genesis",
        signer="@v1",
        pubkey="attacker-v1",
        sig="forged-timeout",
    )
    assert bft.accept_vote(vote_json=vote.to_json(), validators=validators, vpub=vpub) is None
    assert (
        bft.accept_timeout(timeout_json=timeout.to_json(), validators=validators, vpub=vpub) is None
    )
    assert bft._votes == {}
    assert bft._timeouts == {}
    assert seen == []
