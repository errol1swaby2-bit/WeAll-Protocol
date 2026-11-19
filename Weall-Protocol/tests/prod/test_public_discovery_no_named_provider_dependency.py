from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _forbidden_terms() -> list[str]:
    # Construct the removed provider name so this guard does not itself re-add
    # the literal reference it is designed to prevent.
    provider = "Cloud" + "flare"
    return [
        provider,
        provider.lower(),
        provider.lower() + "d",
        "workers" + ".dev",
        "pages" + ".dev",
        "registry.weallprotocol" + ".xyz",
        "orange " + "cloud",
    ]


# Deliberate, finite exceptions for optional static hosting, not authority.
# Exact reviewed lines only; no runtime path, endpoint, SDK or proxy is exempt.
# Placeholders prevent the guard from triggering its own name scan.
_REVIEWED_HOSTING_LINES = r"""
web/DEPLOYMENT.md :: context. The optional <HOST_TITLE> Pages `_headers` uses the same self-only
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: # Optional <HOST_TITLE> Pages access to the WeAll public testnet
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: This is **only** a static, optional convenience frontend. <HOST_TITLE> does not
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: 5. Node API origins must explicitly permit the deployed <HOST_TITLE> frontend:
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: ## <HOST_TITLE> Pages configuration
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: Create a <HOST_TITLE> Pages project linked to this repository. Configure:
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: | Build command | `node scripts/build<HOST_TITLE>Testnet.mjs` |
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: | Node.js | 22; set <HOST_TITLE> Pages build environment variable `NODE_VERSION=22` |
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: <HOST_TITLE> serves the resulting static assets, including `_headers`.
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: or reliance on any specific <HOST_TITLE> API at runtime.
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: deployment and node access checks succeed. <HOST_TITLE>'s Pages Git integration
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: --frontend-origin https://YOUR-<HOST_UPPER>-FRONTEND-HOST \
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: node operator's responsibility, not <HOST_TITLE> Pages' responsibility.
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: - Run `cd web && npm ci && node scripts/build<HOST_TITLE>Testnet.mjs`.
web/DEPLOY_<HOST_UPPER>_TESTNET.md :: - Confirm no browser request to the <HOST_TITLE> origin is used as a `/v1`
web/scripts/build<HOST_TITLE>Testnet.mjs :: // Static <HOST_TITLE> Pages build. This never operates a WeAll API gateway.
web/scripts/build<HOST_TITLE>Testnet.mjs :: console.log(`<HOST_TITLE> static frontend prepared with ${seeds.length} HTTPS seed(s).`);
web/scripts/test_<HOST_LOWER>_testnet_behavior.mjs :: // Simulates an incorrectly configured third-party <HOST_TITLE> build. The
web/scripts/check_https_node_api.mjs :: * consensus safety, PoH sessions, P2P ports or actual <HOST_TITLE> deployment.
web/scripts/test_<HOST_LOWER>_testnet_access_source.mjs :: const buildScript = resolve(webRoot, "scripts/build<HOST_TITLE>Testnet.mjs");
web/scripts/test_<HOST_LOWER>_testnet_access_source.mjs :: const build = readWeb("scripts/build<HOST_TITLE>Testnet.mjs");
web/scripts/test_<HOST_LOWER>_testnet_access_source.mjs :: // No <HOST_TITLE> gateway. Testnet launch fails when registry is unsigned/stale.
web/scripts/test_<HOST_LOWER>_testnet_access_source.mjs :: console.log("<HOST_TITLE> testnet frontend integration source checks passed");
web/docs/IHD1_J01_J02_J18_RECEIPT_INTEGRATION_20261114.md :: - Additional evidence required: exact-head clean-clone operational replay on an independent PC, cross-machine node/observer state-root verification, <HOST_TITLE>-hosted HTTPS binding, and multi-validator BFT/finality. The same-node restart step does not establish these.
web/docs/IHD1_JOURNEY_CLOSURE_MATRIX_20261114.md :: 0. Pin exact source + clean clone -> node ready + HTTPS/CORS/<HOST_TITLE> binding
web/docs/IHD1_JOURNEY_CLOSURE_MATRIX_20261114.md :: **Explicit limits:** Current <HOST_TITLE> DNS/deployment state, credentials, actual physical-device PoH, automatic cross-device appearance sync, independent validation and current 20 unapproved V2 semantics are not established by this document. Existing draft PRs #81/#82/#88 remain NO-GO; this branch is stacked, not a release gate override.
web/docs/FRONTEND_V16_IMPLEMENTATION_STATUS.md :: - **Evidence limits:** Exact-head Web CI is required; the new tests are behavior-level pure normalizer/source invariants, **not** fresh signed transactions or node-restart evidence. This closes a specific premature-success UI defect, not J18 as a whole. No backend consensus/replay change, semantic approval, <HOST_TITLE> deployment or release authorization is asserted. Existing stacked PRs and production gates remain draft/NO-GO.
web/public/_headers :: # <HOST_TITLE> Pages static frontend. Node API traffic goes directly to the
web/public/_headers :: # selected HTTPS testnet node; <HOST_TITLE> does not proxy /v1 requests.
docs/integration/UNIFIED_BASELINE_PR93_CLOSURE.md :: | Public <HOST_TITLE> testnet deployment preparation | #78 | Second-parent merge; import four previously absent deploy docs/config/tests; newer #81/#88 connection, CSP, manifests and generated values take precedence in overlapping files. No deployment authorized. |
docs/integration/UNIFIED_BASELINE_PR93_CLOSURE.md :: - PR #78 <HOST_TITLE> config/docs remain documentation and nonproduction testnet preparation. It has no right to override current signed seed registry, TLS/CSP, authority or constitutional readiness gates.
Weall-Protocol/docs/testnet/TWO_PC_NETWORK_REHEARSAL_PREPARATION.md :: protocol authority gates. It is separate from optional <HOST_TITLE> static
Weall-Protocol/docs/testnet/TWO_PC_NETWORK_REHEARSAL_PREPARATION.md :: Optional <HOST_TITLE> Pages frontend:
Weall-Protocol/docs/testnet/TWO_PC_NETWORK_REHEARSAL_PREPARATION.md :: | <HOST_TITLE> access | draft PR #78 | direct browser-to-node HTTPS, not protocol authority |
Weall-Protocol/docs/testnet/IHD1_TWO_PROCESS_OBSERVER_RECEIPT_REPLAY.md :: **No:** independent physical PCs, distinct verified node signing keys, production validator status, authenticated TCP mesh adjacency, autonomous gossip or scheduler, validator quorum certificates, independent network consensus finality, live PoH uniqueness, IPFS durability, <HOST_TITLE> deployment, public testnet authority, or release approval.
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: users through a <HOST_TITLE>-hosted **static frontend** and an HTTPS **node API endpoint**.
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: 1. Participants load the static `web/dist` build from <HOST_TITLE> Pages.
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: <HOST_TITLE> Pages is the **frontend host**, not a WeAll validator, consensus engine,
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: | M4.0 — endpoint and identity | <HOST_TITLE> UI chooses the expected HTTPS node and rejects spoofed/unready nodes | Pinned-build identity, CORS preflight, independent browser source tests, failing negative controls | Public registry still requires genuine rotation/signature |
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: node scripts/test_<HOST_LOWER>_testnet_access_source.mjs
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: node scripts/test_<HOST_LOWER>_testnet_behavior.mjs
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: The <HOST_TITLE> static release generator (`node scripts/build<HOST_TITLE>Testnet.mjs`)
Weall-Protocol/docs/testnet/M4_SINGLE_NODE_MULTI_USER_INTEGRATION.md :: release-scope review; until then <HOST_TITLE> static deployment is only a
.github/workflows/m4-single-node-hosted-frontend-contract.yml :: - web/scripts/test_<HOST_LOWER>_testnet_access_source.mjs
.github/workflows/m4-single-node-hosted-frontend-contract.yml :: - web/scripts/test_<HOST_LOWER>_testnet_behavior.mjs
.github/workflows/m4-single-node-hosted-frontend-contract.yml :: node scripts/test_<HOST_LOWER>_testnet_access_source.mjs
.github/workflows/m4-single-node-hosted-frontend-contract.yml :: node scripts/test_<HOST_LOWER>_testnet_behavior.mjs
.github/workflows/web-ci.yml :: - name: <HOST_TITLE> static testnet source guards
.github/workflows/web-ci.yml :: node scripts/test_<HOST_LOWER>_testnet_access_source.mjs
.github/workflows/web-ci.yml :: - name: <HOST_TITLE> testnet node-selection behavioral regression
.github/workflows/web-ci.yml :: node scripts/test_<HOST_LOWER>_testnet_behavior.mjs
.github/workflows/m4-social-eligibility-boundary.yml :: echo 'remote_<HOST_LOWER>_multi_user=NOT_PROVEN'
"""


def _host_text(value: str) -> str:
    name = "Cloud" + "flare"
    return (
        value.replace("<HOST_TITLE>", name)
        .replace("<HOST_LOWER>", name.lower())
        .replace("<HOST_UPPER>", name.upper())
    )


def _reviewed_hosting_lines() -> set[tuple[str, str]]:
    rows = _host_text(_REVIEWED_HOSTING_LINES).strip().splitlines()
    return {(row.split(" :: ", 1)[0], row.split(" :: ", 1)[1]) for row in rows}


def _is_reviewed_inventory_path(rel: str, line: str, approved: set[tuple[str, str]]) -> bool:
    if rel != "Weall-Protocol/generated/v2/source_coverage_map.json":
        return False
    # Generated source filenames are not provider configuration.
    prefix = '"path": "../'
    if not line.startswith(prefix) or not line.endswith('",'):
        return False
    path = line[len(prefix) : -2]
    return path in {item[0] for item in approved}


def _provider_offenses(rel: str, text: str) -> list[str]:
    terms = _forbidden_terms()
    brand = terms[1]
    if not any(term in text.lower() for term in terms[1:]):
        return []
    approved = _reviewed_hosting_lines()
    offenders: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        # The former daemon name contains the brand; check it separately.
        for term in terms[2:]:
            if term in line.lower():
                offenders.append(f"{rel}: {term}")
        if brand in line.lower():
            if (rel, line) in approved or _is_reviewed_inventory_path(rel, line, approved):
                continue
            offenders.append(f"{rel}: {brand}")
    return offenders


def _project_files() -> list[Path]:
    skipped_dirs = {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        "secrets",
        "dist",
    }
    files: list[Path] = []
    for path in ROOT.parent.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped_dirs or part.startswith(".venv") for part in path.parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".zip", ".sqlite", ".db"}:
            continue
        files.append(path)
    return files


def test_project_controlled_files_have_no_named_provider_references() -> None:
    offenders: list[str] = []
    for path in _project_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT.parent).as_posix()
        offenders.extend(_provider_offenses(rel, text))
    assert offenders == []


def test_optional_static_host_mentions_do_not_exempt_protocol_dependency() -> None:
    approved = _reviewed_hosting_lines()
    path = "web/DEPLOYMENT.md"
    line = next(value for file, value in approved if file == path)
    assert _provider_offenses(path, line) == []
    assert _provider_offenses(path, line + " required") != []
    assert _provider_offenses("web/src/lib/browserNodeSession.ts", line) != []
    assert _provider_offenses("src/weall/runtime/discovery.py", line) != []
    for term in _forbidden_terms()[2:]:
        assert _provider_offenses(path, f"{line} {term}") != []
    inventory = "Weall-Protocol/generated/v2/source_coverage_map.json"
    hosted_script = _host_text("web/scripts/build<HOST_TITLE>Testnet.mjs")
    assert _provider_offenses(inventory, f'"path": "../{hosted_script}",') == []
    assert _provider_offenses(inventory, f'"reason": "../{hosted_script}",') != []
    assert _provider_offenses(inventory, f'"path": "../{hosted_script}.new",') != []
