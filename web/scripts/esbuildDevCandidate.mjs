// Isolated remediation candidate: not release-approved, no HMR yet.
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { createServer, request } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { readFile, realpath, stat } from 'node:fs/promises';
import { basename, dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { parseArgs } from 'node:util';
import { permitsLocalSecretRequest, protectDevBootstrapSecrets } from './devBootstrapLoopbackGuard.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: {
  host: { type: 'string', default: '127.0.0.1' },
  port: { type: 'string', default: '5173' },
  strictPort: { type: 'boolean' },
  force: { type: 'boolean' },
}, strict: true });
assert.ok(['127.0.0.1', 'localhost', '::1'].includes(values.host), 'loopback-only frontend bind');
const port = Number(values.port);
assert.ok(Number.isInteger(port) && port > 0 && port <= 65535, 'invalid port');
const host = values.host === 'localhost' ? '127.0.0.1' : values.host;
const backend = new URL(process.env.VITE_WEALL_DEV_PROXY_TARGET || 'http://127.0.0.1:8000');
assert.ok(backend.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(backend.hostname)
  && !backend.username && !backend.password && backend.pathname === '/' && !backend.search && !backend.hash,
  'loopback HTTP backend required');
const ipfs = new URL('http://127.0.0.1:8080');
const publicKeys = [
  'VITE_WEALL_APP_NAME','VITE_WEALL_ENV_LABEL','VITE_WEALL_ENABLE_DEV_TOOLS',
  'VITE_WEALL_ENABLE_DEV_BOOTSTRAP','VITE_WEALL_CLIENT_NAME','VITE_WEALL_CLIENT_VERSION',
  'VITE_WEALL_PUBLIC_TESTNET','VITE_WEALL_API_BASE','VITE_WEALL_SEED_MANIFEST_URL','VITE_WEALL_SEEDS_URL',
  'VITE_WEALL_EXPECTED_CHAIN_ID','VITE_WEALL_EXPECTED_GENESIS_HASH','VITE_WEALL_EXPECTED_TX_INDEX_HASH',
  'VITE_WEALL_EXPECTED_PROTOCOL_PROFILE_HASH','VITE_WEALL_DEV_BOOTSTRAP_MANIFEST',
  'VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE','VITE_WEALL_ALLOW_CENTRALIZED_LIVE_ROOM_URL',
  'VITE_WEALL_LIVE_ROOM_BASE_URL','VITE_WEALL_LIVE_ROOM_EMBED','VITE_WEALL_ENABLE_POH_TIER2_VIDEO_UPLOAD',
  'VITE_WEALL_ENABLE_BOOTSTRAP_LIVE','VITE_WEALL_MEDIA_REPLICATION_FACTOR',
  'VITE_WEALL_MEDIA_DURABLE_OPERATOR_COUNT','VITE_WEALL_SHOW_TESTNET_CAPABILITY_SURFACE',
];
const env = { PROD: false, DEV: true, MODE: 'development', BASE_URL: '/', SSR: false };
for (const key of publicKeys) if (process.env[key] !== undefined) env[key] = process.env[key];
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
let sha = 'nogit';
try { sha = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(); } catch {}
const out = mkdtempSync(resolve(tmpdir(), 'weall-esbuild-dev-'));
try {
  mkdirSync(resolve(out, 'assets'));
  const result = await build({
    absWorkingDir: root, entryPoints: ['src/main.tsx'], bundle: true,
    format: 'esm', platform: 'browser', target: 'es2022', jsx: 'automatic',
    splitting: true, sourcemap: false, metafile: true, outdir: resolve(out, 'assets'),
    entryNames: '[name]-[hash]', chunkNames: 'chunk-[hash]', assetNames: '[name]-[hash]',
    loader: { '.svg':'file','.png':'file','.jpg':'file','.jpeg':'file','.webp':'file','.gif':'file','.woff':'file','.woff2':'file' },
    define: {
      'import.meta.env': JSON.stringify(env), 'process.env.NODE_ENV': JSON.stringify('development'),
      '__WEALL_WEB_VERSION__': JSON.stringify(pkg.version), '__WEALL_WEB_GIT_SHA__': JSON.stringify(sha),
    },
  });
  const entries = Object.entries(result.metafile.outputs).filter(([p,m]) => p.endsWith('.js') && m.entryPoint === 'src/main.tsx');
  assert.equal(entries.length, 1);
  const [entry, meta] = entries[0];
  assert.ok(meta.cssBundle);
  const tag = '<script type="module" src="/src/main.tsx"></script>';
  const html = readFileSync(resolve(root,'index.html'),'utf8');
  assert.ok(html.includes(tag));
  writeFileSync(resolve(out,'index.html'),html.replace(tag,'<script type="module" src="/assets/'+basename(entry)+'"></script>').replace('</head>','<link rel="stylesheet" href="/assets/'+basename(meta.cssBundle)+'" />\n</head>'));
} catch (error) { rmSync(out,{recursive:true,force:true}); throw error; }

const CSP = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: http: https:; font-src 'self' data:; media-src 'self' blob: http: https:; connect-src 'self' http: https: ws: wss:; worker-src 'self' blob:; frame-src 'self' http://127.0.0.1:* http://localhost:*;";
const headers = { 'Content-Security-Policy': CSP, 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY', 'Permissions-Policy':'geolocation=(), microphone=(self), camera=(self)', 'Cross-Origin-Opener-Policy':'same-origin', 'Cross-Origin-Resource-Policy':'same-origin', 'Cache-Control':'no-store' };
const types = { '.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.gif':'image/gif','.ico':'image/x-icon','.woff':'font/woff','.woff2':'font/woff2','.txt':'text/plain; charset=utf-8','.webmanifest':'application/manifest+json' };
function deny(res,status=403) { res.writeHead(status,headers); res.end(); }
function cleanHeaders(source) {
  const blocked = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto']);
  for (const key of String(source.connection||'').split(',')) blocked.add(key.trim().toLowerCase());
  return Object.fromEntries(Object.entries(source).filter(([key])=>!blocked.has(key.toLowerCase())));
}
function proxy(req,res,target) {
  const upstream = request(target,{method:req.method,path:req.url,headers:{...cleanHeaders(req.headers),host:target.host}},incoming=>{
    res.writeHead(incoming.statusCode||502,{...cleanHeaders(incoming.headers),...headers});
    incoming.pipe(res);
  });
  upstream.setTimeout(30000,()=>upstream.destroy());
  upstream.on('error',()=>{ if (!res.headersSent) deny(res,502); else res.destroy(); });
  req.on('aborted',()=>upstream.destroy());
  res.on('close',()=>upstream.destroy());
  req.pipe(upstream);
}
async function staticFile(req,res,pathname) {
  if (!['GET','HEAD'].includes(req.method)) return deny(res,405);
  const base = pathname === '/' || pathname.startsWith('/assets/') ? out : resolve(root,'public');
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
  try {
    const baseReal = await realpath(base);
    const file = await realpath(resolve(base,rel));
    if (!file.startsWith(baseReal+sep) || !(await stat(file)).isFile()) return deny(res,404);
    const mime = types[extname(file).toLowerCase()];
    if (!mime || rel.split('/').some(p=>p.startsWith('.'))) return deny(res,404);
    const data = await readFile(file);
    res.writeHead(200,{...headers,'Content-Type':mime,'Content-Length':data.length});
    res.end(req.method==='HEAD'?undefined:data);
  } catch { deny(res,404); }
}
const server = createServer((req,res)=>{
  if (!permitsLocalSecretRequest({remoteAddress:req.socket.remoteAddress,host:req.headers.host,origin:req.headers.origin,fetchSite:req.headers['sec-fetch-site']})) return deny(res);
  // Never normalize ambiguous request paths into privileged proxy routes.
  const raw = String(req.url||'').split('?')[0];
  if (!raw.startsWith('/') || raw.startsWith('//') || /[\\\x00-\x20]/.test(raw) || /%(?:2f|5c|25|00|2e)/i.test(raw) || raw.split('/').some(p=>p==='.'||p==='..')) return deny(res,400);
  let pathname;
  try { pathname=decodeURIComponent(raw); } catch { return deny(res,400); }
  protectDevBootstrapSecrets(req,res,()=>{
    if (pathname==='/v1'||pathname.startsWith('/v1/')) return proxy(req,res,backend);
    if (pathname==='/ipfs'||pathname.startsWith('/ipfs/')) return proxy(req,res,ipfs);
    void staticFile(req,res,pathname);
  });
});
server.on('error',error=>{ console.error(error); rmSync(out,{recursive:true,force:true}); process.exitCode=1; });
server.listen(port,host,()=>console.log('WeAll diagnostic frontend listening on '+host+':'+port));
for (const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>{server.close(()=>{rmSync(out,{recursive:true,force:true});process.exit(0);});server.closeAllConnections();});
