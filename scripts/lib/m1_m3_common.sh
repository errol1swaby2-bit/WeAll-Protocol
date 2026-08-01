#!/usr/bin/env bash
set -Eeuo pipefail

m13_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

m13_identity() {
  local root="$1"
  if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local branch commit tree dirty
    branch="$(git -C "$root" branch --show-current)"
    commit="$(git -C "$root" rev-parse HEAD)"
    tree="$(git -C "$root" rev-parse 'HEAD^{tree}')"
    dirty="$(git -C "$root" status --porcelain --untracked-files=all)"
    printf 'repository_mode=git\nbranch=%s\ncommit=%s\ntree=%s\nclean=%s\n' \
      "${branch:-DETACHED}" "$commit" "$tree" "$([[ -z "$dirty" ]] && echo true || echo false)"
  else
    printf 'repository_mode=source_export\nbranch=UNAVAILABLE\ncommit=UNAVAILABLE\ntree=UNAVAILABLE\nclean=UNVERIFIABLE\n'
  fi
}

m13_require_git_freeze() {
  local root="$1" requested="$2"
  git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo 'ERROR: formal freeze-bound operation requires a real Git worktree; source exports are insufficient.' >&2
    return 2
  }
  local freeze head tree dirty
  freeze="$(git -C "$root" rev-parse "${requested}^{commit}")"
  head="$(git -C "$root" rev-parse HEAD)"
  tree="$(git -C "$root" rev-parse "${freeze}^{tree}")"
  [[ "$head" == "$freeze" ]] || {
    printf 'ERROR: HEAD must equal implementation freeze. head=%s freeze=%s\n' "$head" "$freeze" >&2
    return 2
  }
  dirty="$(git -C "$root" status --porcelain --untracked-files=all)"
  [[ -z "$dirty" ]] || {
    echo 'ERROR: implementation worktree must be clean.' >&2
    printf '%s\n' "$dirty" >&2
    return 2
  }
  printf '%s\t%s\n' "$freeze" "$tree"
}

m13_make_tmp() {
  local prefix="$1"
  umask 077
  mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX"
}

m13_run_gate() {
  local results="$1" logs="$2" name="$3"
  shift 3
  local slug rc command_text
  slug="$(printf '%s' "$name" | tr '[:upper:] ' '[:lower:]_' | tr -cd 'a-z0-9_.-')"
  printf -v command_text '%q ' "$@"
  echo "[M1-M3] $name"
  set +e
  (set -o pipefail; "$@") >"$logs/${slug}.log" 2>&1
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    printf '%s\tpassed\t0\t%s\t%s\n' "$name" "$logs/${slug}.log" "$command_text" >> "$results"
    echo "[M1-M3] PASS $name"
  else
    printf '%s\tfailed\t%s\t%s\t%s\n' "$name" "$rc" "$logs/${slug}.log" "$command_text" >> "$results"
    echo "[M1-M3] FAIL $name — see $logs/${slug}.log" >&2
  fi
  return "$rc"
}

m13_write_json_summary() {
  local results="$1" identity="$2" out="$3" mode="$4"
  python3 - "$results" "$identity" "$out" "$mode" <<'PY'
import json, pathlib, sys
results = pathlib.Path(sys.argv[1])
identity = pathlib.Path(sys.argv[2])
out = pathlib.Path(sys.argv[3])
mode = sys.argv[4]
idata={}
for line in identity.read_text(encoding='utf-8').splitlines():
    if '=' in line:
        k,v=line.split('=',1); idata[k]=v
rows=[]
for line in results.read_text(encoding='utf-8').splitlines():
    if not line.strip(): continue
    name,status,rc,log,command=line.split('\t',4)
    rows.append({'name':name,'status':status,'return_code':int(rc),'log':log,'command':command.strip()})
obj={'schema':'weall.m1_m3.gate_summary.v1','mode':mode,'identity':idata,'all_passed':all(r['status']=='passed' for r in rows),'gate_count':len(rows),'gates':rows}
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')
print(json.dumps(obj,sort_keys=True))
PY
}
