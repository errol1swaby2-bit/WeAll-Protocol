import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { browserBuildEnvironment } from './esbuildEnvironment.mjs';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Test entries are explicit, share the application's module graph, and are
// never emitted in a production build or ordinary development server.
export const browserTestEntries = Object.freeze({
  "keys": "src/auth/keys.ts",
  "session": "src/auth/session.ts",
  "recoveryFile": "src/auth/recoveryFile.ts",
  "evidenceCrypto": "src/auth/evidenceCrypto.ts",
  "weall": "src/api/weall.ts",
});

export async function buildFrontend(out, production, { browserTests = false } = {}) {
  assert.ok(!production || !browserTests, 'browser test modules cannot be built for production');
  const env = browserBuildEnvironment(root, production);
  const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  let sha = 'nogit';
  try { sha = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(); } catch {}
  mkdirSync(resolve(out, 'assets'), { recursive: true });
  const result = await build({
    absWorkingDir: root, entryPoints: { main: 'src/main.tsx', ...(browserTests ? Object.fromEntries(Object.entries(browserTestEntries).map(([name, path]) => ['test-' + name, path])) : {}) }, bundle: true,
    format: 'esm', platform: 'browser', target: 'es2022', jsx: 'automatic',
    splitting: true, minify: production, sourcemap: false, metafile: true, outdir: resolve(out, 'assets'),
    entryNames: '[name]-[hash]', chunkNames: 'chunk-[hash]', assetNames: '[name]-[hash]',
    loader: { '.svg':'file','.png':'file','.jpg':'file','.jpeg':'file','.webp':'file','.gif':'file','.woff':'file','.woff2':'file' },
    define: {
      'import.meta.env': JSON.stringify(env), 'process.env.NODE_ENV': JSON.stringify(production ? 'production' : 'development'),
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
  if (browserTests) {
    const dir = resolve(out, '__weall_test__');
    mkdirSync(dir, { recursive: true });
    for (const [name, source] of Object.entries(browserTestEntries)) {
      const matches = Object.entries(result.metafile.outputs).filter(([p, m]) => p.endsWith('.js') && m.entryPoint === source);
      assert.equal(matches.length, 1, 'missing browser test entry: ' + name);
      const asset = basename(matches[0][0]);
      writeFileSync(resolve(dir, name + '.js'), 'export * from "/assets/' + asset + '";\n');
    }
  }
  if (production) {
    // Explicit public deployment assets only. Local tester bootstrap manifests
    // and any unreviewed public-directory files must never be shipped.
    for (const filename of ['_headers', 'seeds.json']) {
      const src = resolve(root, 'public', filename);
      assert.ok(existsSync(src), 'Missing deployment asset: ' + filename);
      copyFileSync(src, resolve(out, filename));
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const out = mkdtempSync(resolve(root, '.esbuild-stage-'));
  try {
    await buildFrontend(out, true);
    const dist = resolve(root, 'dist');
    rmSync(dist, { recursive: true, force: true });
    renameSync(out, dist);
    console.log('WeAll production build emitted to dist');
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
