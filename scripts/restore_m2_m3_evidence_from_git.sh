#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M2_FREEZE="${M2_HISTORICAL_FREEZE_COMMIT:-017cadc8d7825036b23fe0bc07156ca763eb52fc}"
M2_EVIDENCE="${M2_HISTORICAL_EVIDENCE_COMMIT:-1d0d36c71fc63ea7383f604e7ea3306898a647fd}"
M3_FREEZE="${M3_HISTORICAL_FREEZE_COMMIT:-4ca0e13e1e4838b8816e977e33f8dd82fae3b7c5}"
M3_EVIDENCE="${M3_HISTORICAL_EVIDENCE_COMMIT:-72b9122e1d67b216cc8d678f921951a5a52175ad}"
VERIFY_ONLY=0
DESTINATION="${ROOT}"

usage() {
  cat <<'USAGE'
Usage: scripts/restore_m2_m3_evidence_from_git.sh [--verify-only] [--destination PATH]

Verifies the historical M2 and M3 implementation-freeze/evidence-only pairs.
Without --verify-only, restores their complete artifact trees from Git objects.
No network access is used; all four commits must already exist locally.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only) VERIFY_ONLY=1; shift ;;
    --destination) DESTINATION="${2:?missing destination}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for cmd in git python3 tar; do
  command -v "${cmd}" >/dev/null 2>&1 || { echo "ERROR: missing command: ${cmd}" >&2; exit 2; }
done

for commit in "${M2_FREEZE}" "${M2_EVIDENCE}" "${M3_FREEZE}" "${M3_EVIDENCE}"; do
  git -C "${ROOT}" cat-file -e "${commit}^{commit}" 2>/dev/null || {
    echo "ERROR: required historical commit is unavailable locally: ${commit}" >&2
    echo "Fetch the repository history before retrying." >&2
    exit 2
  }
done

[[ "$(git -C "${ROOT}" rev-parse "${M2_EVIDENCE}^")" == "$(git -C "${ROOT}" rev-parse "${M2_FREEZE}")" ]] || {
  echo "ERROR: M2 evidence commit is not the direct child of the declared freeze" >&2; exit 1;
}
[[ "$(git -C "${ROOT}" rev-parse "${M3_EVIDENCE}^")" == "$(git -C "${ROOT}" rev-parse "${M3_FREEZE}")" ]] || {
  echo "ERROR: M3 evidence commit is not the direct child of the declared freeze" >&2; exit 1;
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/weall_historical_evidence_XXXXXX")"
cleanup() {
  git -C "${ROOT}" worktree remove --force "${TMP}/m2" >/dev/null 2>&1 || true
  git -C "${ROOT}" worktree remove --force "${TMP}/m3" >/dev/null 2>&1 || true
  rm -rf "${TMP}"
}
trap cleanup EXIT INT TERM

git -C "${ROOT}" worktree add --detach "${TMP}/m2" "${M2_EVIDENCE}" >/dev/null
git -C "${ROOT}" worktree add --detach "${TMP}/m3" "${M3_EVIDENCE}" >/dev/null

(
  cd "${TMP}/m2"
  python3 scripts/check_m2_evidence_manifest.py \
    --mode commit \
    --freeze-commit "${M2_FREEZE}" \
    --commit "${M2_EVIDENCE}"
)
(
  cd "${TMP}/m3"
  M3_IMPLEMENTATION_FREEZE_COMMIT="${M3_FREEZE}" \
    bash scripts/check_m3_evidence_only_commit.sh
)

if [[ "${VERIFY_ONLY}" == "1" ]]; then
  echo "OK: historical M2 and M3 evidence pairs verified"
  exit 0
fi

mkdir -p "${DESTINATION}/artifacts"
rm -rf "${DESTINATION}/artifacts/m2-closure" "${DESTINATION}/artifacts/m3-closure"
(
  cd "${DESTINATION}"
  git -C "${ROOT}" archive "${M2_EVIDENCE}" artifacts/m2-closure | tar -xf -
  git -C "${ROOT}" archive "${M3_EVIDENCE}" artifacts/m3-closure | tar -xf -
)

echo "OK: restored complete historical evidence trees under ${DESTINATION}/artifacts"
