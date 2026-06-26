#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const REPO = path.resolve(ROOT, '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');
const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
};
const assert = (cond, msg) => {
  if (!cond) fail(msg);
};
const includes = (src, needle, msg) => assert(src.includes(needle), `${msg}: missing ${needle}`);
const notIncludes = (src, needle, msg) => assert(!src.includes(needle), `${msg}: legacy/shim remains: ${needle}`);

const router = read('web/src/lib/router.ts');
notIncludes(router, 'ROUTE_ALIASES', 'route aliases must be removed');
for (const route of ['"/juror"', '"/tools"', '"/poh"', '"/proposals"', '"/disputes"']) {
  notIncludes(router, route, 'legacy route metadata and match branches must be removed');
}
includes(router, '"/reviews"', 'canonical Review Center route must remain');
includes(router, '"/advanced"', 'canonical Advanced route must remain');

const prefetch = read('web/src/lib/routePrefetch.ts');
includes(prefetch, '"/home": () => import("../pages/HomeDashboard")', 'prefetch must use canonical Home wrapper');
includes(prefetch, '"/verification": () => import("../pages/PohPage")', 'prefetch must use canonical PoH wrapper');
for (const route of ['"/juror"', '"/tools"', '"/poh"', '"/proposals"', '"/disputes"']) {
  notIncludes(prefetch, route, 'legacy prefetch route must be removed');
}

const juror = read('web/src/pages/JurorDashboard.tsx');
notIncludes(juror, 'Review assigned community work', 'compatibility review wording must be removed');
notIncludes(juror, 'Open live room', 'legacy live-room wording must be removed');
includes(juror, 'Live room transport is only available after a live PoH reviewer assignment is active', 'current live transport boundary must be visible');

const live = read('web/src/pages/LiveVerificationRoom.tsx');
notIncludes(live, 'Open live room', 'legacy live-room status wording must be removed');
notIncludes(live, 'Open the compatibility transport', 'compatibility transport language must be removed');
includes(live, 'Live room transport controls unlock only for the subject or assigned reviewers', 'direct live transport boundary must be visible');

const accountVerification = read('web/src/pages/AccountVerificationPage.tsx');
notIncludes(accountVerification, 'Advanced compatibility controls', 'advanced PoH compatibility controls must be removed');
notIncludes(accountVerification, 'Open compatibility review', 'Tier-2 compatibility review UI must be removed');
notIncludes(accountVerification, 'pohTier2TxRequest', 'legacy Tier-2 tx request client call must be removed from UI');
notIncludes(accountVerification, 'Open compatibility transport', 'compatibility transport UI wording must be removed');

const keys = read('web/src/auth/keys.ts');
notIncludes(keys, 'KEYRING_PREFIX', 'legacy browser keyring prefix must be removed');
notIncludes(keys, 'weall.keyring', 'legacy browser keyring storage must be removed');
notIncludes(keys, 'legacySecret', 'silent localStorage secret migration must be removed');
includes(keys, 'sessionStorage.setItem(secretStorageKey(normalized), secretKeyB64)', 'secret must remain session-scoped');
includes(keys, 'localStorage.setItem(keyStorageKey(normalized), JSON.stringify(secureMeta))', 'public metadata storage must remain');

const api = read('web/src/api/weall.ts');
notIncludes(api, 'pohLiveJurorCases', 'legacy live juror-cases client helper must be removed');
notIncludes(api, 'pohTier2TxRequest', 'legacy Tier-2 request client helper must be removed');
notIncludes(api, 'pohTier2TxJurorAccept', 'legacy Tier-2 accept client helper must be removed');
notIncludes(api, 'pohTier2TxJurorDecline', 'legacy Tier-2 decline client helper must be removed');
notIncludes(api, 'pohTier2TxReview', 'legacy Tier-2 review client helper must be removed');
notIncludes(api, '/v1/poh/tier2/tx/juror-accept', 'legacy Tier-2 accept endpoint must be absent from web client');
notIncludes(api, '/v1/poh/tier2/tx/juror-decline', 'legacy Tier-2 decline endpoint must be absent from web client');
notIncludes(api, '/v1/poh/tier2/tx/review', 'legacy Tier-2 review endpoint must be absent from web client');
notIncludes(api, '/v1/poh/live/juror-cases', 'legacy live juror-cases route must be absent from web client');
notIncludes(api, '/v1/poh/tier2/tx/request', 'legacy Tier-2 skeleton route must be absent from web client');

const txSchema = read('Weall-Protocol/src/weall/runtime/tx_schema.py');
notIncludes(txSchema, 'AliasChoices', 'canonical tx schema must not accept broad payload aliases');
notIncludes(txSchema, 'validation_alias=', 'canonical tx schema must not accept validation aliases');

const apiErrors = read('Weall-Protocol/src/weall/api/errors.py');
includes(apiErrors, 'def gone', 'API must support explicit 410 Gone for removed legacy endpoints');

const pohRoutes = read('Weall-Protocol/src/weall/api/routes_public_parts/poh.py');
includes(pohRoutes, 'return False', 'header-scoped restricted PoH compatibility must be disabled');
includes(pohRoutes, '/v1/poh/live/juror-cases has been removed', 'legacy live juror-cases endpoint must return 410');
includes(pohRoutes, '/v1/poh/tier2/tx/request has been removed', 'legacy Tier-2 skeleton endpoint must return 410');
notIncludes(pohRoutes, 'WEALL_DEV_ALLOW_HEADER_SCOPED_PRIVATE_POH', 'header-scoped restricted PoH env shim must be removed');

const executor = read('Weall-Protocol/src/weall/runtime/executor.py');
notIncludes(executor, 'self._store = self._ledger_store', 'executor storage alias must be removed');
notIncludes(executor, 'def snapshot(self)', 'executor snapshot compatibility method must be removed');
includes(executor, 'def read_state(self)', 'executor direct state reader must remain');

const health = read('Weall-Protocol/src/weall/api/routes_public_parts/health.py');
includes(health, 'def _try_executor_state', 'health readiness must use direct executor state helper');
includes(health, 'read_state = getattr(ex, "read_state", None)', 'health readiness must call read_state directly');
notIncludes(health, '_try_executor_snapshot', 'health readiness snapshot helper must be removed');
notIncludes(health, 'getattr(ex, "snapshot"', 'health readiness must not use executor snapshot compatibility');


const statusRoutes = read('Weall-Protocol/src/weall/api/routes_public_parts/status.py');
notIncludes(statusRoutes, '_try_executor_snapshot', 'status routes must not use executor snapshot fallback');
notIncludes(statusRoutes, 'getattr(ex, "snapshot"', 'status routes must read executor state directly');
includes(statusRoutes, 'fn = getattr(ex, "read_state", None)', 'status routes must use read_state helper');

const netSelfRoutes = read('Weall-Protocol/src/weall/api/routes_public_parts/net_self.py');
includes(netSelfRoutes, 'def _try_executor_state', 'net self must use direct executor state helper');
includes(netSelfRoutes, 'fn = getattr(ex, "read_state", None)', 'net self must call read_state directly');
notIncludes(netSelfRoutes, '_try_executor_snapshot', 'net self snapshot helper must be removed');
notIncludes(netSelfRoutes, 'getattr(ex, "snapshot"', 'net self must not use executor snapshot compatibility');

const helperReadinessRoutes = read('Weall-Protocol/src/weall/api/routes_public_parts/helper_readiness.py');
includes(helperReadinessRoutes, 'read_state = getattr(ex, "read_state", None)', 'helper readiness must call read_state directly');
notIncludes(helperReadinessRoutes, 'getattr(ex, "snapshot"', 'helper readiness must not use executor snapshot compatibility');

const disputeDetail = read('web/src/pages/DisputeDetail.tsx');
notIncludes(disputeDetail, 'Legacy Inspect report only', 'report detail must not mention legacy inspect wording');

const liveRoomLib = read('web/src/lib/liveRoom.ts');
notIncludes(liveRoomLib, 'compatibility escape hatch', 'live room library must not describe hosted transport as compatibility');
notIncludes(liveRoomLib, 'LEGACY_CENTRALIZED_ROOM_BASE_URL', 'live room library must not retain legacy URL constant name');

const prefetchRoutes = read('web/src/lib/routePrefetch.ts');
includes(prefetchRoutes, 'function routePatternForPath', 'route prefetch must resolve concrete dynamic paths');
includes(prefetchRoutes, 'part.startsWith(":")', 'route prefetch must match dynamic route segments');

const diagnostics = read('Weall-Protocol/src/weall/runtime/diagnostics.py');
notIncludes(diagnostics, 'def snapshot(self)', 'diagnostics snapshot compatibility function must be removed');

console.log('OK: Batch 626-632 direct protocol no-legacy-shims source checks passed');
