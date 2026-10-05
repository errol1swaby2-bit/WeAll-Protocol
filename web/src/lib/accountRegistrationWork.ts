import { apiGet } from "../api/weall";

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
