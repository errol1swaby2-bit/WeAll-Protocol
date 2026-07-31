#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${WEALL_RELEASE_OUTPUT_DIR:-${ROOT}/release/m1-m3-integrated}"
UNSIGNED=0
usage() {
  cat <<'USAGE'
Usage: scripts/build_signed_m1_m3_release.sh [--unsigned-rehearsal]

Required environment:
  M1_M3_IMPLEMENTATION_FREEZE_COMMIT
  M1_M3_EVIDENCE_COMMIT

Optional:
  WEALL_RELEASE_GPG_KEY       GPG key fingerprint or ID.
  WEALL_RELEASE_OUTPUT_DIR    Output directory.

The default path requires detached GPG signatures. --unsigned-rehearsal creates
an explicitly marked rehearsal package and may not be described as a release.
USAGE
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --unsigned-rehearsal) UNSIGNED=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for cmd in git python3 gzip sha256sum; do
  command -v "${cmd}" >/dev/null 2>&1 || { echo "ERROR: missing command: ${cmd}" >&2; exit 2; }
done
FREEZE="${M1_M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
EVIDENCE="${M1_M3_EVIDENCE_COMMIT:-}"
[[ -n "${FREEZE}" && -n "${EVIDENCE}" ]] || { usage >&2; exit 2; }
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
EVIDENCE="$(git -C "${ROOT}" rev-parse "${EVIDENCE}^{commit}")"
[[ "$(git -C "${ROOT}" rev-parse "${EVIDENCE}^")" == "${FREEZE}" ]] || {
  echo "ERROR: evidence commit is not the direct child of the implementation freeze" >&2; exit 1;
}
(
  cd "${ROOT}"
  M1_M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
    python3 scripts/check_m1_m3_integrated_evidence.py \
      --mode commit --freeze-commit "${FREEZE}" --commit "${EVIDENCE}"
)

STAMP="${WEALL_RELEASE_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
LABEL="WeAll-M1-M3-${EVIDENCE:0:12}-${STAMP}"
mkdir -p "${OUT}"
ARCHIVE="${OUT}/${LABEL}.tar.gz"
PROVENANCE="${OUT}/${LABEL}.provenance.json"
CHECKSUMS="${OUT}/${LABEL}.SHA256SUMS"

git -C "${ROOT}" archive --format=tar --prefix="${LABEL}/" "${EVIDENCE}" | gzip -n > "${ARCHIVE}"
python3 - "${ROOT}" "${FREEZE}" "${EVIDENCE}" "${ARCHIVE}" "${PROVENANCE}" "${UNSIGNED}" <<'PY'
from __future__ import annotations
import hashlib, json, subprocess, sys
from pathlib import Path
root=Path(sys.argv[1]); freeze=sys.argv[2]; evidence=sys.argv[3]
archive=Path(sys.argv[4]); out=Path(sys.argv[5]); unsigned=bool(int(sys.argv[6]))
def git(*args): return subprocess.check_output(["git",*args],cwd=root,text=True).strip()
def sha(path):
 h=hashlib.sha256(); h.update(path.read_bytes()); return h.hexdigest()
def bind(rel):
 p=root/rel; return {"path":rel,"sha256":sha(p),"size_bytes":p.stat().st_size}
profile=root/"Weall-Protocol/configs/consensus_profiles/weall-m1-m3-production-v1.json"
profile_obj=json.loads(profile.read_text())
value={
 "schema":"weall.m1_m3.detached_release.v1",
 "release_status":"unsigned_rehearsal" if unsigned else "signed_release_candidate",
 "implementation_freeze_commit":freeze,
 "implementation_tree":git("rev-parse",f"{freeze}^{{tree}}"),
 "evidence_commit":evidence,
 "evidence_tree":git("rev-parse",f"{evidence}^{{tree}}"),
 "archive":{"name":archive.name,"sha256":sha(archive),"size_bytes":archive.stat().st_size},
 "consensus_profile_manifest_hash":profile_obj.get("manifest_hash"),
 "bindings":[bind("Weall-Protocol/requirements.lock"),bind("Weall-Protocol/requirements-dev.lock"),bind("web/package-lock.json"),bind("docker/Dockerfile.m1-m3-closure"),bind("Weall-Protocol/configs/consensus_profiles/weall-m1-m3-production-v1.json")],
 "authorization_boundary":"Spec-M1, M2 controlled-testnet account/PoH, and R-M3 controlled-testnet civic/governance current-head roll-forward only.",
 "exclusions":["Mainnet authorization","public multi-validator BFT authorization","live economics","production validator admission","production executable governance","independent external security review"],
}
out.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
PY
(
  cd "${OUT}"
  sha256sum "$(basename "${ARCHIVE}")" "$(basename "${PROVENANCE}")" > "$(basename "${CHECKSUMS}")"
)

if [[ "${UNSIGNED}" == "0" ]]; then
  command -v gpg >/dev/null 2>&1 || { echo "ERROR: gpg is required" >&2; exit 2; }
  GPG_ARGS=(--armor --detach-sign)
  if [[ -n "${WEALL_RELEASE_GPG_KEY:-}" ]]; then
    GPG_ARGS+=(--local-user "${WEALL_RELEASE_GPG_KEY}")
  fi
  gpg "${GPG_ARGS[@]}" "${ARCHIVE}"
  gpg "${GPG_ARGS[@]}" "${PROVENANCE}"
  gpg "${GPG_ARGS[@]}" "${CHECKSUMS}"
fi

echo "OK: release package written to ${OUT}"
