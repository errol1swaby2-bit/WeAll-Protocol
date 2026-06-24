import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');

const router = read('src/lib/router.ts');
const app = read('src/App.tsx');
const api = read('src/api/weall.ts');
const activity = read('src/pages/Activity.tsx');
const accountVerification = read('src/pages/AccountVerificationPage.tsx');

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

assert(!router.includes('path: "/' + 'mess' + 'ages"'), 'router must not include removed communication route match');
assert(!router.includes('href: "/' + 'mess' + 'ages"'), 'nav must not link removed communication route');
assert(!router.includes('rightRail: "messaging"'), 'route metadata must not use messaging rail');
assert(router.includes('path: "/activity"'), 'router must expose /activity');
assert(app.includes('import("./pages/Activity")'), 'App must lazy-load Activity page');
assert(!app.includes('Mess' + 'agingKeyBootstrapper'), 'App must not mount removed communication key bootstrapper');
assert(!app.includes('case "/' + 'mess' + 'ages"'), 'App must not route removed communication path');
assert(!api.includes('messageThreads('), 'API client must not expose removed thread list');
assert(!api.includes('messageThread('), 'API client must not expose removed thread detail');
assert(activity.includes('publicly inspectable protocol events') || activity.includes('public protocol events'), 'Activity page must state public-event derivation');
assert(activity.includes('mentions') && activity.includes('validator/operator alerts'), 'Activity page must list public notice types');

console.log('OK: public-only frontend source contract holds');
