import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
function read(rel) { return fs.readFileSync(path.join(root, rel), 'utf8'); }
function exists(rel) { return fs.existsSync(path.join(root, rel)); }
function assertIncludes(file, needle) { const text = read(file); if (!text.includes(needle)) throw new Error(`${file} missing ${needle}`); }

assertIncludes('src/pages/Economics.tsx', 'Economics & Treasury');
assertIncludes('src/pages/Economics.tsx', 'Genesis economics locked');
assertIncludes('src/api/weall.ts', 'economicsStatus');
assertIncludes('src/api/weall.ts', 'walletStatus');
assertIncludes('src/lib/router.ts', 'href: "/economics"');
if (exists('src/lib/' + 'message' + 'Crypto.ts')) throw new Error('removed private communication crypto module returned');
if (exists('src/pages/' + 'Mess' + 'aging.tsx')) throw new Error('removed private communication page returned');

console.log('batch457 economics/block/public checks passed');
