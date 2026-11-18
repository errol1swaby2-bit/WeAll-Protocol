// Loopback-only development and local production preview. Restart after source edits; no HMR.
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { readFile, realpath, stat } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { parseArgs } from 'node:util';
import { permitsLocalSecretRequest, protectDevBootstrapSecrets } from './devBootstrapLoopbackGuard.mjs';

import { buildFrontend, root } from './esbuildBuild.mjs';

const preview = process.argv[2] === 'preview';
const { values } = parseArgs({ args: process.argv.slice(preview ? 3 : 2), options: {
  host: { type: 'string', default: '127.0.0.1' },
  port: { type: 'string', default: preview ? '4173' : '5173' },
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
const out = preview ? resolve(root, 'dist') : mkdtempSync(resolve(tmpdir(), 'weall-esbuild-dev-'));
function cleanup() { if (!preview) rmSync(out,{recursive:true,force:true}); }
try {
  if (preview) assert.ok((await stat(resolve(out, 'index.html'))).isFile(), 'build before preview');
  else await buildFrontend(out, false);
} catch (error) { cleanup(); throw error; }

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
  const base = preview || pathname === '/' || pathname.startsWith('/assets/') ? out : resolve(root,'public');
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
    if (pathname==='/v1'||pathname.startsWith('/v1/')) return preview ? deny(res,404) : proxy(req,res,backend);
    if (pathname==='/ipfs'||pathname.startsWith('/ipfs/')) return preview ? deny(res,404) : proxy(req,res,ipfs);
    void staticFile(req,res,pathname);
  });
});
server.on('error',error=>{ console.error(error); cleanup(); process.exitCode=1; });
server.listen(port,host,()=>console.log('WeAll frontend listening on '+host+':'+port));
for (const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>{server.close(()=>{cleanup();process.exit(0);});server.closeAllConnections();});
