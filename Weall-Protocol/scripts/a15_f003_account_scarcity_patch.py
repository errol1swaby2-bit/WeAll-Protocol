from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"replace_once_failed:{path}:count={count}:needle={old[:80]!r}")
    write(path, text.replace(old, new, 1))


write(
    "src/weall/runtime/account_registration_work.py",
    '''from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .tx_admission_types import TxEnvelope

Json = dict[str, Any]

ACCOUNT_REGISTRATION_WORK_VERSION = "sha256-v1"
ACCOUNT_REGISTRATION_WORK_DOMAIN = "weall.account_register_work.v1"
ACCOUNT_REGISTRATION_WORK_MIN_BITS = 1
ACCOUNT_REGISTRATION_WORK_MAX_BITS = 30
ACCOUNT_REGISTRATION_WORK_MAX_NONCE = (1 << 53) - 1


@dataclass(frozen=True)
class AccountRegistrationWorkPolicy:
    required: bool
    difficulty_bits: int
    valid: bool = True
    reason: str = ""


def _as_params(state: Json) -> Json:
    params = state.get("params") if isinstance(state, dict) else None
    return params if isinstance(params, dict) else {}


def _policy_bool(value: Any) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    if value is None:
        return False, True
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True, True
    if text in {"0", "false", "no", "off", ""}:
        return False, True
    return False, False


def account_registration_work_policy(state: Json) -> AccountRegistrationWorkPolicy:
    params = _as_params(state)
    required, required_valid = _policy_bool(params.get("account_registration_work_required"))
    if not required_valid:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            valid=False,
            reason="registration_work_required_policy_invalid",
        )
    if not required:
        return AccountRegistrationWorkPolicy(required=False, difficulty_bits=0)

    raw_bits = params.get("account_registration_work_difficulty_bits")
    if isinstance(raw_bits, bool):
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            valid=False,
            reason="registration_work_difficulty_invalid",
        )
    try:
        bits = int(raw_bits)
    except Exception:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            valid=False,
            reason="registration_work_difficulty_invalid",
        )
    if bits < ACCOUNT_REGISTRATION_WORK_MIN_BITS or bits > ACCOUNT_REGISTRATION_WORK_MAX_BITS:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=bits,
            valid=False,
            reason="registration_work_difficulty_out_of_range",
        )
    return AccountRegistrationWorkPolicy(required=True, difficulty_bits=bits)


def _payload_without_work(payload: Any) -> Json:
    if not isinstance(payload, dict):
        return {}
    return {
        str(k): v
        for k, v in payload.items()
        if str(k) not in {"registration_work_version", "registration_work_nonce"}
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def account_registration_work_preimage(env: TxEnvelope, work_nonce: int) -> bytes:
    payload_json = _canonical_json(_payload_without_work(env.payload))
    preimage = [
        ACCOUNT_REGISTRATION_WORK_DOMAIN,
        ACCOUNT_REGISTRATION_WORK_VERSION,
        str(getattr(env, "chain_id", "") or "").strip(),
        str(env.signer or "").strip(),
        int(env.nonce),
        str(getattr(env, "sig_profile", "") or "").strip(),
        getattr(env, "parent", None),
        payload_json,
        int(work_nonce),
    ]
    return _canonical_json(preimage).encode("utf-8")


def account_registration_work_digest(env: TxEnvelope, work_nonce: int) -> bytes:
    return hashlib.sha256(account_registration_work_preimage(env, work_nonce)).digest()


def leading_zero_bits(digest: bytes) -> int:
    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
            continue
        total += 8 - int(byte).bit_length()
        break
    return total


def verify_account_registration_work(
    state: Json, env: TxEnvelope
) -> tuple[bool, str, Json]:
    if str(env.tx_type or "").strip().upper() != "ACCOUNT_REGISTER":
        return True, "", {}

    policy = account_registration_work_policy(state)
    if not policy.valid:
        return False, policy.reason or "registration_work_policy_invalid", {
            "required": bool(policy.required),
            "difficulty_bits": int(policy.difficulty_bits),
        }
    if not policy.required:
        return True, "", {}

    payload = env.payload if isinstance(env.payload, dict) else {}
    version = str(payload.get("registration_work_version") or "").strip()
    if version != ACCOUNT_REGISTRATION_WORK_VERSION:
        return False, "registration_work_version_required", {
            "expected": ACCOUNT_REGISTRATION_WORK_VERSION,
        }

    raw_nonce = payload.get("registration_work_nonce")
    if isinstance(raw_nonce, bool):
        return False, "registration_work_nonce_invalid", {}
    try:
        work_nonce = int(raw_nonce)
    except Exception:
        return False, "registration_work_nonce_invalid", {}
    if work_nonce < 0 or work_nonce > ACCOUNT_REGISTRATION_WORK_MAX_NONCE:
        return False, "registration_work_nonce_out_of_range", {
            "max_nonce": ACCOUNT_REGISTRATION_WORK_MAX_NONCE,
        }

    digest = account_registration_work_digest(env, work_nonce)
    actual_bits = leading_zero_bits(digest)
    if actual_bits < policy.difficulty_bits:
        return False, "registration_work_insufficient", {
            "required_bits": int(policy.difficulty_bits),
            "actual_bits": int(actual_bits),
        }
    return True, "", {
        "version": ACCOUNT_REGISTRATION_WORK_VERSION,
        "difficulty_bits": int(policy.difficulty_bits),
        "actual_bits": int(actual_bits),
    }


def account_registration_work_policy_json(state: Json) -> Json:
    policy = account_registration_work_policy(state)
    return {
        "required": bool(policy.required),
        "difficulty_bits": int(policy.difficulty_bits),
        "valid": bool(policy.valid),
        "reason": str(policy.reason or ""),
        "version": ACCOUNT_REGISTRATION_WORK_VERSION,
        "max_nonce": ACCOUNT_REGISTRATION_WORK_MAX_NONCE,
    }


__all__ = [
    "ACCOUNT_REGISTRATION_WORK_DOMAIN",
    "ACCOUNT_REGISTRATION_WORK_MAX_BITS",
    "ACCOUNT_REGISTRATION_WORK_MAX_NONCE",
    "ACCOUNT_REGISTRATION_WORK_MIN_BITS",
    "ACCOUNT_REGISTRATION_WORK_VERSION",
    "AccountRegistrationWorkPolicy",
    "account_registration_work_digest",
    "account_registration_work_policy",
    "account_registration_work_policy_json",
    "account_registration_work_preimage",
    "leading_zero_bits",
    "verify_account_registration_work",
]
''',
)

replace_once(
    "src/weall/runtime/tx_schema.py",
    '''    evidence_kem_pubkey: str | None = Field(default=None, min_length=1)\n    evidence_kem_algorithm: str | None = Field(default=None, min_length=1)\n''',
    '''    evidence_kem_pubkey: str | None = Field(default=None, min_length=1)\n    evidence_kem_algorithm: str | None = Field(default=None, min_length=1)\n    registration_work_version: str | None = Field(default=None, min_length=1, max_length=64)\n    registration_work_nonce: int | None = Field(default=None, ge=0, le=9007199254740991)\n''',
)

replace_once(
    "src/weall/runtime/tx_admission.py",
    '''from weall.runtime.account_id import is_valid_account_id, strict_account_ids_enabled\n''',
    '''from weall.runtime.account_id import is_valid_account_id, strict_account_ids_enabled\nfrom weall.runtime.account_registration_work import verify_account_registration_work\n''',
)
replace_once(
    "src/weall/runtime/tx_admission.py",
    '''    bad = _mvp_payload_checks(env)\n    if bad is not None:\n        return bad\n\n    bad = _sig_ok(env, context=ctx)\n''',
    '''    bad = _mvp_payload_checks(env)\n    if bad is not None:\n        return bad\n\n    # A15-F003: permanent account creation must carry consensus-visible scarcity\n    # before we spend ML-DSA verification work on an unknown fresh key.\n    if tx_type_norm == "ACCOUNT_REGISTER":\n        work_ok, work_reason, work_meta = verify_account_registration_work(lv.to_ledger(), env)\n        if not work_ok:\n            return _rej("registration_work_invalid", work_reason, **work_meta)\n\n    bad = _sig_ok(env, context=ctx)\n''',
)

replace_once(
    "src/weall/runtime/apply/identity.py",
    '''from ..account_recovery_policy import (\n''',
    '''from ..account_registration_work import verify_account_registration_work\nfrom ..account_recovery_policy import (\n''',
)
replace_once(
    "src/weall/runtime/apply/identity.py",
    '''    p = _payload(env)\n    key_record = _key_record_from_payload_or_raise(state, p, key_type="main")\n''',
    '''    p = _payload(env)\n    work_ok, work_reason, work_meta = verify_account_registration_work(state, env)\n    if not work_ok:\n        raise ApplyError("invalid_tx", work_reason, work_meta)\n\n    key_record = _key_record_from_payload_or_raise(state, p, key_type="main")\n''',
)

replace_once(
    "src/weall/runtime/genesis_bootstrap.py",
    '''        "require_recovery_key_at_account_register": bool(strict_identity_registration),\n        "require_evidence_kem_at_account_register": bool(strict_identity_registration),\n        "block_tx_signature_policy": (\n''',
    '''        "require_recovery_key_at_account_register": bool(strict_identity_registration),\n        "require_evidence_kem_at_account_register": bool(strict_identity_registration),\n        # A15-F003: new production/public-testnet identities require a signed,\n        # chain-bound registration work proof before materializing Tier-0 state.\n        "account_registration_work_required": bool(strict_identity_registration),\n        "account_registration_work_difficulty_bits": 16 if strict_identity_registration else 0,\n        "block_tx_signature_policy": (\n''',
)

for path in (
    "scripts/build_production_genesis_manifest.py",
    "scripts/gen_public_testnet_v1_chain_identity.py",
):
    replace_once(
        path,
        '''            "require_recovery_key_at_account_register": True,\n            "require_evidence_kem_at_account_register": True,\n            "bft_signing_public_beta_gate_enabled": True,\n''',
        '''            "require_recovery_key_at_account_register": True,\n            "require_evidence_kem_at_account_register": True,\n            "account_registration_work_required": True,\n            "account_registration_work_difficulty_bits": 16,\n            "bft_signing_public_beta_gate_enabled": True,\n''',
    )

replace_once(
    "src/weall/api/routes_public_parts/accounts.py",
    '''from weall.ledger.state import LedgerView\n''',
    '''from weall.ledger.state import LedgerView\nfrom weall.runtime.account_registration_work import account_registration_work_policy_json\n''',
)
replace_once(
    "src/weall/api/routes_public_parts/accounts.py",
    '''    evidence_kem_pubkey: str | None = Field(default=None, max_length=8192)\n    evidence_kem_algorithm: str | None = Field(default="ml-kem-768", max_length=64)\n    parent: str | None = Field(default=None, max_length=256)\n''',
    '''    evidence_kem_pubkey: str | None = Field(default=None, max_length=8192)\n    evidence_kem_algorithm: str | None = Field(default="ml-kem-768", max_length=64)\n    registration_work_version: str | None = Field(default=None, max_length=64)\n    registration_work_nonce: int | None = Field(default=None, ge=0, le=9007199254740991)\n    parent: str | None = Field(default=None, max_length=256)\n''',
)
replace_once(
    "src/weall/api/routes_public_parts/accounts.py",
    '''                **(\n                    {\n                        "evidence_kem_pubkey": str(req.evidence_kem_pubkey).strip(),\n                        "evidence_kem_algorithm": str(\n                            req.evidence_kem_algorithm or "ml-kem-768"\n                        ).strip(),\n                    }\n                    if req.evidence_kem_pubkey\n                    else {}\n                ),\n            },\n        },\n    }\n\n\n@router.post("/accounts/tx/profile-update")\n''',
    '''                **(\n                    {\n                        "evidence_kem_pubkey": str(req.evidence_kem_pubkey).strip(),\n                        "evidence_kem_algorithm": str(\n                            req.evidence_kem_algorithm or "ml-kem-768"\n                        ).strip(),\n                    }\n                    if req.evidence_kem_pubkey\n                    else {}\n                ),\n                **(\n                    {\n                        "registration_work_version": str(req.registration_work_version).strip(),\n                        "registration_work_nonce": int(req.registration_work_nonce),\n                    }\n                    if req.registration_work_version is not None\n                    and req.registration_work_nonce is not None\n                    else {}\n                ),\n            },\n        },\n    }\n\n\n@router.get("/accounts/registration-work-policy")\ndef v1_account_registration_work_policy(request: Request) -> dict[str, Any]:\n    """Expose the consensus registration-work policy without solving work for clients."""\n    st = _snapshot(request)\n    policy = account_registration_work_policy_json(st)\n    return {\n        "ok": True,\n        "chain_id": str(st.get("chain_id") or ""),\n        "policy": policy,\n        "truth_boundary": "consensus_state_params",\n        "solver": "client_side_only",\n    }\n\n\n@router.post("/accounts/tx/profile-update")\n''',
)

write(
    "../web/src/lib/accountRegistrationWork.ts",
    '''import { apiGet } from "../api/weall";

export const ACCOUNT_REGISTRATION_WORK_VERSION = "sha256-v1";
export const ACCOUNT_REGISTRATION_WORK_DOMAIN = "weall.account_register_work.v1";
const MAX_CLIENT_DIFFICULTY_BITS = 20;
const MAX_WORK_NONCE = Number.MAX_SAFE_INTEGER;
const BATCH_SIZE = 256;

export type AccountRegistrationWorkPolicy = {
  required: boolean;
  difficulty_bits: number;
  valid: boolean;
  reason?: string;
  version: string;
  max_nonce: number;
};

export type AccountRegistrationWorkPolicyResponse = {
  ok: boolean;
  chain_id: string;
  policy: AccountRegistrationWorkPolicy;
};

function canonicalValue(value: any): any {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    const out: Record<string, any> = {};
    for (const key of Object.keys(value).sort()) out[key] = canonicalValue(value[key]);
    return out;
  }
  return value;
}

function canonicalJson(value: any): string {
  return JSON.stringify(canonicalValue(value));
}

function payloadWithoutWork(payload: Record<string, any>): Record<string, any> {
  const out = { ...(payload || {}) };
  delete out.registration_work_version;
  delete out.registration_work_nonce;
  return out;
}

function leadingZeroBits(bytes: Uint8Array): number {
  let total = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      total += 8;
      continue;
    }
    let mask = 0x80;
    while ((byte & mask) === 0) {
      total += 1;
      mask >>= 1;
    }
    break;
  }
  return total;
}

async function sha256(text: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

function preimage(args: {
  chainId: string;
  signer: string;
  txNonce: number;
  sigProfile: string;
  parent: string | null;
  payload: Record<string, any>;
  workNonce: number;
}): string {
  const payloadJson = canonicalJson(payloadWithoutWork(args.payload));
  return canonicalJson([
    ACCOUNT_REGISTRATION_WORK_DOMAIN,
    ACCOUNT_REGISTRATION_WORK_VERSION,
    String(args.chainId || "").trim(),
    String(args.signer || "").trim(),
    Math.max(0, Math.floor(Number(args.txNonce || 0))),
    String(args.sigProfile || "").trim(),
    args.parent ?? null,
    payloadJson,
    Math.max(0, Math.floor(Number(args.workNonce || 0))),
  ]);
}

export async function fetchAccountRegistrationWorkPolicy(base?: string): Promise<AccountRegistrationWorkPolicyResponse> {
  const response = await apiGet<AccountRegistrationWorkPolicyResponse>("/v1/accounts/registration-work-policy", base);
  if (!response?.ok || !response.policy) throw new Error("registration_work_policy_unavailable");
  if (!response.policy.valid) throw new Error(response.policy.reason || "registration_work_policy_invalid");
  if (response.policy.required && response.policy.version !== ACCOUNT_REGISTRATION_WORK_VERSION) {
    throw new Error("unsupported_registration_work_version");
  }
  return response;
}

export async function solveAccountRegistrationWork(args: {
  policyResponse: AccountRegistrationWorkPolicyResponse;
  signer: string;
  txNonce: number;
  sigProfile: string;
  parent: string | null;
  payload: Record<string, any>;
}): Promise<Record<string, any>> {
  const policy = args.policyResponse.policy;
  if (!policy.required) return {};
  const bits = Math.floor(Number(policy.difficulty_bits || 0));
  if (bits < 1 || bits > MAX_CLIENT_DIFFICULTY_BITS) {
    throw new Error(`registration_work_difficulty_unsupported:${bits}`);
  }

  const maxAttempts = Math.min(MAX_WORK_NONCE, 2 ** Math.min(bits + 6, 30));
  for (let start = 0; start <= maxAttempts; start += BATCH_SIZE) {
    const count = Math.min(BATCH_SIZE, maxAttempts - start + 1);
    const candidates = Array.from({ length: count }, (_, index) => start + index);
    const digests = await Promise.all(
      candidates.map((workNonce) =>
        sha256(
          preimage({
            chainId: args.policyResponse.chain_id,
            signer: args.signer,
            txNonce: args.txNonce,
            sigProfile: args.sigProfile,
            parent: args.parent,
            payload: args.payload,
            workNonce,
          }),
        ),
      ),
    );
    for (let index = 0; index < digests.length; index += 1) {
      if (leadingZeroBits(digests[index]) >= bits) {
        return {
          registration_work_version: ACCOUNT_REGISTRATION_WORK_VERSION,
          registration_work_nonce: candidates[index],
        };
      }
    }
    if ((start / BATCH_SIZE) % 16 === 15) {
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    }
  }
  throw new Error("registration_work_solution_not_found_within_bound");
}
''',
)

replace_once(
    "../web/src/auth/session.ts",
    '''  payloadFactory: (nonce: number) => any;\n''',
    '''  payloadFactory: (nonce: number) => any | Promise<any>;\n''',
)
replace_once(
    "../web/src/auth/session.ts",
    '''      const payload = args.payloadFactory(nonce);\n''',
    '''      const payload = await args.payloadFactory(nonce);\n''',
)
replace_once(
    "../web/src/auth/session.ts",
    '''  payloadFactory: (nonce: number) => any;\n''',
    '''  payloadFactory: (nonce: number) => any | Promise<any>;\n''',
)
replace_once(
    "../web/src/auth/session.ts",
    '''      const payload = args.payloadFactory(claim.nonce);\n''',
    '''      const payload = await args.payloadFactory(claim.nonce);\n''',
)

replace_once(
    "../web/src/pages/AccountVerificationPage.tsx",
    '''  submitSignedTx,\n  submitSignedTxInSequence,\n''',
    '''  submitSignedTx,\n  submitSignedTxInSequence,\n  submitSignedTxWithNonce,\n''',
)
replace_once(
    "../web/src/pages/AccountVerificationPage.tsx",
    '''import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";\n''',
    '''import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";\nimport {\n  fetchAccountRegistrationWorkPolicy,\n  solveAccountRegistrationWork,\n} from "../lib/accountRegistrationWork";\n''',
)
old_register = '''        task: async () => submitSignedTx({\n          account: acct,\n          tx_type: "ACCOUNT_REGISTER",\n          payload: {\n            pubkey: kp.pubkeyB64,\n            recovery_pubkey: ensureRecoveryAuthorityKeypair(acct).pubkeyB64,\n            recovery_sig_profile: "pq-mldsa-v1",\n            evidence_kem_pubkey: ensureEvidenceKemKeypair(acct).publicKeyB64,\n            evidence_kem_algorithm: "ml-kem-768",\n          },\n          parent: null,\n          base,\n        }),\n'''
new_register = '''        task: async () => {\n          const recoveryPubkey = ensureRecoveryAuthorityKeypair(acct).pubkeyB64;\n          const evidenceKemPubkey = ensureEvidenceKemKeypair(acct).publicKeyB64;\n          const policyResponse = await fetchAccountRegistrationWorkPolicy(base);\n          const submitted = await submitSignedTxWithNonce({\n            account: acct,\n            tx_type: "ACCOUNT_REGISTER",\n            payloadFactory: async (nonce) => {\n              const payload = {\n                pubkey: kp.pubkeyB64,\n                recovery_pubkey: recoveryPubkey,\n                recovery_sig_profile: "pq-mldsa-v1",\n                evidence_kem_pubkey: evidenceKemPubkey,\n                evidence_kem_algorithm: "ml-kem-768",\n              };\n              const work = await solveAccountRegistrationWork({\n                policyResponse,\n                signer: acct,\n                txNonce: nonce,\n                sigProfile: "pq-mldsa-v1",\n                parent: null,\n                payload,\n              });\n              return { ...payload, ...work };\n            },\n            parent: null,\n            base,\n          });\n          return submitted.result;\n        },\n'''
replace_once("../web/src/pages/AccountVerificationPage.tsx", old_register, new_register)

write(
    "tests/test_a15_f003_account_registration_scarcity.py",
    '''from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.account_registration_work import (
    ACCOUNT_REGISTRATION_WORK_VERSION,
    account_registration_work_digest,
    account_registration_work_policy,
    leading_zero_bits,
    verify_account_registration_work,
)
from weall.runtime.tx_admission_types import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def _env(*, signer: str = "@alice", nonce: int = 1, pubkey: str = "pk-a") -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "chain_id": "weall-prod",
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "sig_profile": "pq-mldsa-v1",
            "payload": {
                "pubkey": pubkey,
                "recovery_pubkey": "recovery-a",
                "recovery_sig_profile": "pq-mldsa-v1",
                "evidence_kem_pubkey": "kem-a",
                "evidence_kem_algorithm": "ml-kem-768",
            },
            "parent": None,
        }
    )


def _state(bits: int = 8) -> dict:
    return {
        "chain_id": "weall-prod",
        "accounts": {},
        "params": {
            "account_registration_work_required": True,
            "account_registration_work_difficulty_bits": bits,
        },
    }


def _solve(env: TxEnvelope, bits: int) -> int:
    for nonce in range(1_000_000):
        if leading_zero_bits(account_registration_work_digest(env, nonce)) >= bits:
            return nonce
    raise AssertionError("test work solution not found")


def _with_work(env: TxEnvelope, bits: int = 8) -> TxEnvelope:
    nonce = _solve(env, bits)
    raw = env.to_json()
    raw["payload"] = dict(raw["payload"])
    raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
    raw["payload"]["registration_work_nonce"] = nonce
    return TxEnvelope.from_json(raw)


def test_historical_policy_absent_remains_replay_compatible() -> None:
    policy = account_registration_work_policy({"params": {}})
    assert policy.valid is True
    assert policy.required is False
    ok, reason, _ = verify_account_registration_work({"params": {}}, _env())
    assert ok is True
    assert reason == ""


@pytest.mark.parametrize(
    "params,reason",
    [
        ({"account_registration_work_required": True}, "registration_work_difficulty_invalid"),
        (
            {
                "account_registration_work_required": True,
                "account_registration_work_difficulty_bits": 0,
            },
            "registration_work_difficulty_out_of_range",
        ),
        (
            {
                "account_registration_work_required": "maybe",
                "account_registration_work_difficulty_bits": 8,
            },
            "registration_work_required_policy_invalid",
        ),
    ],
)
def test_required_policy_fails_closed_when_invalid(params: dict, reason: str) -> None:
    policy = account_registration_work_policy({"params": params})
    assert policy.valid is False
    ok, got, _ = verify_account_registration_work({"params": params}, _env())
    assert ok is False
    assert got == reason


def test_valid_work_is_bound_to_full_registration_identity() -> None:
    env = _with_work(_env(), 8)
    ok, reason, meta = verify_account_registration_work(_state(8), env)
    assert ok is True
    assert reason == ""
    assert meta["difficulty_bits"] == 8

    variants = [
        _env(signer="@mallory"),
        _env(nonce=2),
        _env(pubkey="pk-b"),
    ]
    work_nonce = env.payload["registration_work_nonce"]
    for variant in variants:
        raw = variant.to_json()
        raw["payload"] = dict(raw["payload"])
        raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
        raw["payload"]["registration_work_nonce"] = work_nonce
        ok2, reason2, _ = verify_account_registration_work(_state(8), TxEnvelope.from_json(raw))
        assert ok2 is False
        assert reason2 == "registration_work_insufficient"


def test_many_signers_cannot_reuse_one_accounts_work() -> None:
    original = _with_work(_env(signer="@acct000"), 8)
    work_nonce = original.payload["registration_work_nonce"]
    accepted = 0
    for index in range(64):
        env = _env(signer=f"@acct{index:03d}")
        raw = env.to_json()
        raw["payload"] = dict(raw["payload"])
        raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
        raw["payload"]["registration_work_nonce"] = work_nonce
        ok, _, _ = verify_account_registration_work(_state(8), TxEnvelope.from_json(raw))
        accepted += int(ok)
    assert accepted == 1


def test_checked_in_production_and_testnet_genesis_require_nonzero_work() -> None:
    for relative in ("configs/genesis.ledger.prod.json", "configs/genesis.ledger.testnet-v1.json"):
        state = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        params = state["params"]
        assert params["account_registration_work_required"] is True
        assert int(params["account_registration_work_difficulty_bits"]) >= 1
        policy = account_registration_work_policy(state)
        assert policy.valid is True
        assert policy.required is True


def test_registration_work_schema_is_signed_payload_surface() -> None:
    from weall.runtime.tx_schema import validate_tx_envelope

    env = _with_work(_env(), 8)
    # Replace cryptographic strings with schema-valid opaque values; this test is
    # about strict payload acceptance, while key decoding is apply-time policy.
    validate_tx_envelope(env.to_json())
''',
)

write(
    "scripts/bench_a15_f003_account_cardinality.py",
    '''from __future__ import annotations

import argparse
import json
import time
from hashlib import sha256


def _account(index: int) -> dict:
    return {
        "nonce": 1,
        "account_type": "human",
        "poh_tier": 0,
        "banned": False,
        "locked": False,
        "reputation": "0",
        "keys": {"by_id": {f"k:{index:016x}": {"pubkey": f"pk:{index:016x}", "revoked": False}}},
        "devices": {"by_id": {}},
        "recovery": {"mode": None, "config": None, "requests": {}, "history": []},
        "evidence_encryption": {"algorithm": None, "public_key": None},
        "session_keys": {},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="A15-F003 synthetic account-cardinality state benchmark")
    parser.add_argument("--accounts", type=int, required=True)
    args = parser.parse_args()
    count = max(0, int(args.accounts))
    started = time.perf_counter()
    state = {"height": 1, "accounts": {f"@synthetic-{i:07d}": _account(i) for i in range(count)}}
    built_s = time.perf_counter() - started
    started = time.perf_counter()
    encoded = json.dumps(state, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    serialize_s = time.perf_counter() - started
    started = time.perf_counter()
    digest = sha256(encoded).hexdigest()
    hash_s = time.perf_counter() - started
    started = time.perf_counter()
    parsed = json.loads(encoded)
    restart_parse_s = time.perf_counter() - started
    if len(parsed["accounts"]) != count:
        raise SystemExit("synthetic_account_count_mismatch")
    print(
        json.dumps(
            {
                "schema": "weall.a15_f003.account_cardinality_benchmark.v1",
                "accounts": count,
                "encoded_bytes": len(encoded),
                "build_seconds": round(built_s, 6),
                "serialize_seconds": round(serialize_s, 6),
                "hash_seconds": round(hash_s, 6),
                "restart_parse_seconds": round(restart_parse_s, 6),
                "sha256": digest,
                "synthetic": True,
                "note": "Synthetic Tier-0 shaped state used for cardinality scaling evidence; not a production throughput benchmark.",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
)

write(
    "docs/security/ACCOUNT_REGISTRATION_SCARCITY.md",
    '''# Account Registration Scarcity Invariant (A15-F003)

## Status and scope

This document records the bounded remediation for A15-F003. It closes the **free fresh-key permanent-state creation** primitive. It does **not** claim that WeAll has solved global one-human uniqueness (A08), and it does not claim a hard lifetime maximum on all legitimate human accounts.

## Consensus invariant

When `params.account_registration_work_required` is true, an `ACCOUNT_REGISTER` transaction MUST carry a supported registration-work version and a work nonce whose SHA-256 digest has at least `params.account_registration_work_difficulty_bits` leading zero bits.

The work preimage is domain-separated and commits to:

- the registration-work domain and version;
- transaction `chain_id`;
- signer / new account ID;
- transaction nonce;
- transaction signature profile;
- parent;
- the entire canonical registration payload excluding only `registration_work_version` and `registration_work_nonce`;
- the work nonce.

The registration-work fields remain inside the transaction payload and are therefore covered by the normal transaction signature.

Production and public-testnet genesis identities require registration work with a finite nonzero difficulty. Historical/ad-hoc states that do not enable the consensus parameter remain replay-compatible.

## Fail-closed rules

A required policy fails closed when its enable flag or difficulty is malformed, when difficulty is outside the supported range, when the proof version is absent/unsupported, when the work nonce is outside the JavaScript-safe integer range, or when the digest does not meet the required difficulty.

Public admission performs this cheap SHA-256 check before ML-DSA signature verification. Block admission repeats it, and `_apply_account_register` verifies it again as defense in depth before materializing the permanent Tier-0 account subtree.

## Accessibility boundary

Registration work is not a protocol fee, deposit, rent, stake, or purchase. It imposes a deterministic one-time computation on permanent account creation while retaining fee-free identity onboarding. The browser solves the proof locally before signing; public nodes expose only the consensus work policy and do not act as proof-solving oracles.

## Security boundary

This mechanism establishes **marginal computational scarcity** for each independently bound permanent registration. A proof solved for one signer, nonce, chain, or registration payload cannot be reused for another. It does not equate an account with a unique physical human, and high-resource attackers can still spend proportionally greater computation to create more accounts. Human uniqueness remains separately owned by A08.

## Closure evidence

Required focused evidence includes:

- production/testnet genesis policy is explicitly enabled and nonzero;
- malformed required policy fails closed;
- work is bound to signer, nonce, and registration payload;
- one account's proof does not bypass many-signer admission;
- strict payload schema carries the signed work fields;
- normal browser onboarding obtains policy, solves work locally, then signs/submits;
- 100k and 1M synthetic Tier-0-shaped state cardinality benchmarks are available through `scripts/bench_a15_f003_account_cardinality.py`;
- full backend, web, canon/current-generated, production-readiness, and exact-head CI remain green.

The cardinality benchmark is scaling evidence, not a production performance certification.
''',
)

print("A15-F003 patch staged")
