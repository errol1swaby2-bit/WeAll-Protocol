from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives import serialization

from weall.api.public_seed_registry import registry_signature_payload, validator_endpoint_signature_payload
from weall.crypto.sig import sign_mldsa

_REGISTRY_SEED = "11" * 32
_VALIDATOR_SEED = "22" * 32


def _pubkey_for_seed(seed_hex: str) -> str:
    key = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


REGISTRY_PUBKEY = _pubkey_for_seed(_REGISTRY_SEED)
VALIDATOR_PUBKEY = _pubkey_for_seed(_VALIDATOR_SEED)


def commitments_for(data: dict) -> dict:
    return {
        "network_id": str(data.get("network_id") or ""),
        "chain_id": str(data.get("chain_id") or ""),
        "genesis_hash": str(data.get("genesis_hash") or ""),
        "protocol_profile_hash": str(data.get("protocol_profile_hash") or ""),
        "tx_index_hash": str(data.get("tx_index_hash") or ""),
    }


def signed_endpoint(data: dict, endpoint: dict, *, seed_hex: str = _VALIDATOR_SEED, pubkey: str = VALIDATOR_PUBKEY) -> dict:
    out = dict(endpoint)
    out.setdefault("node_pubkey", pubkey)
    out.setdefault("signer", pubkey)
    out["signature"] = sign_mldsa(
        message=validator_endpoint_signature_payload(out, commitments=commitments_for(data)),
        privkey=seed_hex,
    )
    out["signed"] = True
    out["verified"] = True
    return out


def signed_registry(data: dict, *, seed_hex: str = _REGISTRY_SEED, pubkey: str = REGISTRY_PUBKEY) -> dict:
    out = dict(data)
    out["seed_registry_signer"] = pubkey
    out["seed_registry_signature_alg"] = "mldsa/weall.public_seed_registry.v1"
    out["seed_registry_signature"] = sign_mldsa(
        message=registry_signature_payload(out),
        privkey=seed_hex,
    )
    return out
