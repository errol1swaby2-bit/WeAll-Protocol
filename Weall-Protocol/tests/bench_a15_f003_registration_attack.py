from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from weall.runtime.account_registration_work import (
    ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS,
    ACCOUNT_REGISTRATION_WORK_VERSION,
    account_registration_work_digest,
    leading_zero_bits,
    verify_account_registration_work,
)
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex

ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"json_root_not_object:{path}")
    return data


def _unsigned_registration(*, signer: str, index: int) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "chain_id": "weall-prod",
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "sig_profile": "pq-mldsa-v1",
            "payload": {
                # This rehearsal measures the pre-signature permanent-state work
                # envelope. Cryptographic key validity is exercised separately by
                # the end-to-end registration regression.
                "pubkey": f"{index + 1:064x}",
            },
            "parent": None,
        }
    )


def _solve(env: TxEnvelope, *, difficulty_bits: int, max_nonce: int) -> tuple[int, int]:
    for work_nonce in range(max_nonce + 1):
        if leading_zero_bits(account_registration_work_digest(env, work_nonce)) >= difficulty_bits:
            return work_nonce, work_nonce + 1
    raise SystemExit(
        f"registration_work_solution_not_found:signer={env.signer}:"
        f"bits={difficulty_bits}:max_nonce={max_nonce}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="A15-F003 distributed fresh-key registration-work attack rehearsal"
    )
    parser.add_argument("--accounts", type=int, default=32)
    parser.add_argument("--max-nonce", type=int, default=5_000_000)
    args = parser.parse_args()

    account_count = max(1, int(args.accounts))
    max_nonce = max(1, int(args.max_nonce))

    state = _load_json(ROOT / "configs" / "genesis.ledger.prod.json")
    params = state.get("params") if isinstance(state.get("params"), dict) else {}
    difficulty_bits = int(params.get("account_registration_work_difficulty_bits") or 0)
    if params.get("account_registration_work_required") is not True:
        raise SystemExit("production_registration_work_not_required")
    if difficulty_bits < ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS:
        raise SystemExit(
            "production_registration_work_below_reviewed_floor:"
            f"{difficulty_bits}<{ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS}"
        )

    canon = TxIndex.load_from_file(ROOT / "generated" / "tx_index.json")
    total_attempts = 0
    solved: list[dict] = []
    started = time.perf_counter()

    for index in range(account_count):
        signer = f"@a15bench{index:04d}"
        unsigned = _unsigned_registration(signer=signer, index=index)
        work_nonce, attempts = _solve(
            unsigned,
            difficulty_bits=difficulty_bits,
            max_nonce=max_nonce,
        )
        total_attempts += attempts

        raw = unsigned.to_json()
        raw["payload"] = dict(raw["payload"])
        raw["payload"]["registration_work_version"] = ACCOUNT_REGISTRATION_WORK_VERSION
        raw["payload"]["registration_work_nonce"] = work_nonce
        env = TxEnvelope.from_json(raw)

        work_ok, work_reason, work_meta = verify_account_registration_work(state, env)
        if not work_ok:
            raise SystemExit(
                f"solved_work_rejected:{signer}:{work_reason}:"
                f"{json.dumps(work_meta, sort_keys=True)}"
            )

        # Exercise canonical transaction admission. Mempool context intentionally
        # isolates the scarcity envelope from ML-DSA signing cost; the end-to-end
        # regression separately signs, builds, commits, and restarts fresh accounts.
        verdict = admit_tx(env, state, canon, context="mempool")
        if not verdict.ok:
            raise SystemExit(
                f"solved_registration_admission_rejected:{signer}:"
                f"{verdict.code}:{verdict.reason}"
            )

        solved.append(
            {
                "signer": signer,
                "work_nonce": int(work_nonce),
                "attempts": int(attempts),
                "actual_bits": int(work_meta.get("actual_bits") or 0),
            }
        )

    elapsed = time.perf_counter() - started
    attempts_per_second = (float(total_attempts) / elapsed) if elapsed > 0 else 0.0
    print(
        json.dumps(
            {
                "schema": "weall.a15_f003.registration_attack_benchmark.v1",
                "chain_id": str(state.get("chain_id") or ""),
                "accounts": account_count,
                "difficulty_bits": difficulty_bits,
                "reviewed_minimum_bits": ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS,
                "total_attempts": total_attempts,
                "mean_attempts_per_account": round(total_attempts / account_count, 3),
                "elapsed_seconds": round(elapsed, 6),
                "attempts_per_second": round(attempts_per_second, 3),
                "all_solved_work_verified": True,
                "all_solved_work_passed_canonical_admission": True,
                "distributed_signers": account_count,
                "solutions": solved,
                "note": (
                    "Deterministic CPU rehearsal of independent production-difficulty "
                    "registration-work solutions and canonical admission. Timing is CI-host "
                    "evidence, not a validator throughput or Sybil-resistance claim."
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
