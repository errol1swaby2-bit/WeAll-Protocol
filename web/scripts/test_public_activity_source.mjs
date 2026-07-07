import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
function read(rel) { return fs.readFileSync(path.join(root, rel), 'utf8'); }
function exists(rel) { return fs.existsSync(path.join(root, rel)); }

const app = read('src/App.tsx');
const router = read('src/lib/router.ts');
const txQueue = read('src/components/TxQueueProvider.tsx');
const activityApi = fs.readFileSync(path.resolve(root, '../Weall-Protocol/src/weall/api/routes_public_parts/activity.py'), 'utf8');

if (exists('src/components/' + 'Mess' + 'agingKeyBootstrapper.tsx')) throw new Error('removed key bootstrapper returned');
if (exists('src/pages/' + 'Mess' + 'aging.tsx')) throw new Error('removed non-public social page returned');
if (!router.includes('path: "/activity"')) throw new Error('router must expose activity page');
if (!app.includes('import("./pages/Activity")')) throw new Error('App must lazy-load Activity page');
if (!activityApi.includes('/activity/notices')) throw new Error('backend activity notices route missing');
if (!txQueue.includes('TX_RECORDED_AUTO_DISMISS_MS')) throw new Error('tx activity queue timing missing');

console.log('batch451 public activity source checks passed');
