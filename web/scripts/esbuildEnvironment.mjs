import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';

// Only reviewed public configuration is exposed to the browser. Never
// serialize process.env, .env files, or the server-only proxy target.
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

export function browserBuildEnvironment(root, production, ambient = process.env) {
  const mode = production ? 'production' : 'development';
  const values = {};
  for (const name of ['.env', '.env.local', '.env.' + mode, '.env.' + mode + '.local']) {
    const path = resolve(root, name);
    if (existsSync(path)) Object.assign(values, parseEnv(readFileSync(path, 'utf8')));
  }
  const env = { PROD: production, DEV: !production, MODE: mode, BASE_URL: '/', SSR: false };
  for (const key of publicKeys) {
    const value = ambient[key] ?? values[key];
    if (value !== undefined) env[key] = String(value);
  }
  if (production) {
    env.VITE_WEALL_ENABLE_DEV_TOOLS = '0';
    env.VITE_WEALL_ENABLE_DEV_BOOTSTRAP = '0';
    delete env.VITE_WEALL_DEV_BOOTSTRAP_MANIFEST;
  }
  return env;
}
